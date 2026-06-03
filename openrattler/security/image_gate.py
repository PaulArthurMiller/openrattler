"""Image attachment security gate.

``ImageAttachmentGate`` enforces five ordered checks against inbound image
attachments before any bytes are downloaded or forwarded to the agent.
Any failing check strips the image and logs an audit event.  Only images
that pass all five checks are downloaded, hashed, and attached to the
``UniversalMessage``.

Two-method design:
- ``check_metadata`` — runs all five checks against Slack-provided metadata
  (no download required).  Returns ``None`` on pass or a human-readable
  rejection reason string on fail.
- ``build_attachment`` — called only when ``check_metadata`` returns ``None``.
  Accepts raw bytes, computes the SHA-256 hash, base64-encodes, builds and
  returns a ``MessageAttachment``.

This split keeps unit tests clean: rejection conditions can be tested without
any HTTP mocking.

SECURITY NOTES
--------------
- Gate check order matters: the channel-enabled check is first so that
  disabled-channel images are silently dropped without reaching any user-facing
  rejection message.
- The per-sender image rate limiter is separate from the message rate limiter —
  image processing is more expensive per turn.
- SHA-256 is used for provenance correlation, not for content integrity
  verification.  An attacker who can intercept the download could substitute
  different bytes; the hash only lets you correlate the audit log to a specific
  received file.
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from openrattler.config.loader import ImageAttachmentConfig
from openrattler.models.audit import AuditEvent
from openrattler.models.messages import MessageAttachment
from openrattler.security.rate_limiter import RateLimiter
from openrattler.storage.audit import AuditLog

# Very high per-minute cap so only the hourly limit ever applies.
_RATE_LIMITER_PER_MINUTE: int = 1_000_000


class ImageAttachmentGate:
    """Security gate for inbound image attachments.

    Checks each candidate image against five ordered conditions before
    downloading any bytes.  Any failure strips the image and continues with
    text-only delivery.  All events (pass and fail) are written to the audit
    log.

    Args:
        config: ``ImageAttachmentConfig`` controlling which senders, types,
                sizes, and rates are permitted.
        audit:  Optional ``AuditLog`` for security event recording.  A ``None``
                audit log is safe — events are silently dropped.
    """

    def __init__(
        self,
        config: ImageAttachmentConfig,
        audit: Optional[AuditLog] = None,
    ) -> None:
        self._config = config
        self._audit = audit
        # Per-minute cap is effectively unlimited; only the hourly limit matters.
        self._rate_limiter = RateLimiter(
            max_per_minute=_RATE_LIMITER_PER_MINUTE,
            max_per_hour=config.max_per_hour,
        )

    @property
    def enabled(self) -> bool:
        """Whether image attachments are enabled for this channel."""
        return self._config.enabled

    async def check_metadata(
        self,
        sender_id: str,
        channel: str,
        content_type: str,
        size_bytes: int,
    ) -> Optional[str]:
        """Run the five gate checks against attachment metadata.

        No bytes are downloaded before this call.  The caller should proceed
        to ``build_attachment`` only when this returns ``None``.

        Args:
            sender_id:    Channel-verified sender identifier (e.g. Slack user ID).
            channel:      Originating channel name (e.g. ``"slack"``).
            content_type: MIME type declared by the channel (e.g. ``"image/jpeg"``).
            size_bytes:   File size in bytes as reported by the channel metadata.

        Returns:
            ``None`` if all checks pass (proceed to ``build_attachment``).
            A human-readable string describing the rejection reason if any
            check fails.  The channel-disabled case returns ``None`` — it is
            silent by design; no rejection message is shown to the sender.

        Security notes:
        - The channel-enabled check is evaluated first so that disabled-channel
          images never reach user-facing rejection messages.
        - ``sender_id`` is only used for allowlist and rate-limit lookups; it
          is never echoed back in rejection messages sent to the user.
        """
        # Check 1: channel must have image attachments enabled.
        if not self._config.enabled:
            await self._audit_event(
                "image_attachment_disabled",
                sender_id=sender_id,
                channel=channel,
                details={"content_type": content_type, "size_bytes": size_bytes},
            )
            # Silent — no rejection message.
            return None

        # Check 2: sender must be in the image allowlist.
        if sender_id not in self._config.sender_allowlist:
            await self._audit_event(
                "image_sender_rejected",
                sender_id=sender_id,
                channel=channel,
                details={"content_type": content_type},
            )
            return "Your image was not accepted: sender not permitted."

        # Check 3: media type must be in the permitted list.
        if content_type not in self._config.permitted_media_types:
            await self._audit_event(
                "image_type_rejected",
                sender_id=sender_id,
                channel=channel,
                details={"content_type": content_type},
            )
            return f"Your image was not accepted: media type '{content_type}' is not permitted."

        # Check 4: size must be within the configured maximum.
        if size_bytes > self._config.max_size_bytes:
            await self._audit_event(
                "image_size_rejected",
                sender_id=sender_id,
                channel=channel,
                details={"size_bytes": size_bytes, "max_size_bytes": self._config.max_size_bytes},
            )
            return (
                f"Your image was not accepted: file size {size_bytes} bytes exceeds "
                f"the {self._config.max_size_bytes}-byte limit."
            )

        # Check 5: sender must be within the hourly rate limit.
        allowed = await self._rate_limiter.check(sender_id)
        if not allowed:
            await self._audit_event(
                "image_rate_limited",
                sender_id=sender_id,
                channel=channel,
                details={"max_per_hour": self._config.max_per_hour},
            )
            return (
                f"Your image was not accepted: hourly limit of "
                f"{self._config.max_per_hour} images exceeded."
            )

        # All checks passed — record the rate-limit hit and signal the caller
        # to proceed to download and build_attachment.
        await self._rate_limiter.record(sender_id)
        return None

    async def build_attachment(
        self,
        sender_id: str,
        channel: str,
        content_type: str,
        raw_bytes: bytes,
    ) -> MessageAttachment:
        """Build a ``MessageAttachment`` from already-downloaded bytes.

        Must only be called after ``check_metadata`` returns ``None`` for the
        same image.  Computes the SHA-256 hash, base64-encodes the bytes, and
        records the ``image_received`` audit event.

        Args:
            sender_id:    Channel-verified sender identifier.
            channel:      Originating channel name.
            content_type: MIME type (same value passed to ``check_metadata``).
            raw_bytes:    Raw image bytes (already downloaded from the channel).

        Returns:
            A ``MessageAttachment`` ready to attach to the ``UniversalMessage``.

        Security notes:
        - SHA-256 is computed from the raw bytes after download, not from the
          Slack-provided metadata.  This gives a reliable provenance fingerprint.
        - ``attachment_id`` is a fresh UUID per image so audit log entries are
          uniquely addressable.
        """
        sha256_hex = hashlib.sha256(raw_bytes).hexdigest()
        b64_data = base64.b64encode(raw_bytes).decode("ascii")
        attachment_id = str(uuid.uuid4())
        received_at = datetime.now(timezone.utc)

        await self._audit_event(
            "image_received",
            sender_id=sender_id,
            channel=channel,
            details={
                "attachment_id": attachment_id,
                "sha256": sha256_hex,
                "content_type": content_type,
                "size_bytes": len(raw_bytes),
            },
        )

        return MessageAttachment(
            attachment_id=attachment_id,
            media_type=content_type,
            data=b64_data,
            size_bytes=len(raw_bytes),
            sha256=sha256_hex,
            origin_channel=channel,
            declared_by_sender=sender_id,
            received_at=received_at,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _audit_event(
        self,
        event: str,
        sender_id: str,
        channel: str,
        details: Optional[dict[str, object]] = None,
    ) -> None:
        """Write an audit event if an ``AuditLog`` is configured."""
        if self._audit is None:
            return
        await self._audit.log(
            AuditEvent(
                event=event,
                agent_id=f"security:image_gate:{channel}",
                details={
                    "sender_id": sender_id,
                    **(details or {}),
                },
            )
        )
