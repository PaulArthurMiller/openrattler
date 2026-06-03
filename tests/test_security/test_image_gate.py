"""Tests for ImageAttachmentGate — the image attachment security gate."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from openrattler.config.loader import ImageAttachmentConfig
from openrattler.security.image_gate import ImageAttachmentGate

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 100  # minimal JPEG-like bytes
_PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
_SMALL_IMAGE = b"\xff\xd8" + b"x" * 50

_DEFAULT_CONFIG = ImageAttachmentConfig(
    enabled=True,
    sender_allowlist=["U_ALLOWED"],
    max_size_bytes=10_485_760,
    max_per_hour=5,
    permitted_media_types=["image/jpeg", "image/png", "image/webp", "image/gif"],
)


def _make_gate(config: ImageAttachmentConfig | None = None) -> ImageAttachmentGate:
    return ImageAttachmentGate(config=config or _DEFAULT_CONFIG, audit=None)


# ---------------------------------------------------------------------------
# check_metadata — rejection conditions
# ---------------------------------------------------------------------------


class TestCheckMetadataRejections:
    async def test_channel_disabled_returns_none_silently(self) -> None:
        cfg = ImageAttachmentConfig(enabled=False, sender_allowlist=["U_ALLOWED"])
        gate = _make_gate(cfg)
        reason = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 1024)
        assert reason is None
        print("[OK] disabled channel returns None silently")

    async def test_sender_not_in_allowlist_returns_rejection(self) -> None:
        gate = _make_gate()
        reason = await gate.check_metadata("U_UNKNOWN", "slack", "image/jpeg", 1024)
        assert reason is not None
        assert "not permitted" in reason
        print("[OK] unknown sender gets rejection reason")

    async def test_type_not_permitted_returns_rejection(self) -> None:
        gate = _make_gate()
        reason = await gate.check_metadata("U_ALLOWED", "slack", "image/tiff", 1024)
        assert reason is not None
        assert "media type" in reason
        print("[OK] disallowed media type gets rejection reason")

    async def test_size_exceeds_limit_returns_rejection(self) -> None:
        cfg = ImageAttachmentConfig(
            enabled=True,
            sender_allowlist=["U_ALLOWED"],
            max_size_bytes=1000,
        )
        gate = _make_gate(cfg)
        reason = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 2000)
        assert reason is not None
        assert "limit" in reason
        print("[OK] oversized image gets rejection reason")

    async def test_rate_limit_exceeded_returns_rejection(self) -> None:
        cfg = ImageAttachmentConfig(
            enabled=True,
            sender_allowlist=["U_ALLOWED"],
            max_per_hour=2,
        )
        gate = _make_gate(cfg)
        # Use up the limit.
        for _ in range(2):
            result = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 100)
            assert result is None
        # Third attempt should be rejected.
        reason = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 100)
        assert reason is not None
        assert "limit" in reason
        print("[OK] rate-limited sender gets rejection reason")

    async def test_all_checks_pass_returns_none(self) -> None:
        gate = _make_gate()
        reason = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 1024)
        assert reason is None
        print("[OK] valid metadata passes all checks")

    async def test_empty_sender_allowlist_blocks_all_senders(self) -> None:
        cfg = ImageAttachmentConfig(enabled=True, sender_allowlist=[])
        gate = _make_gate(cfg)
        reason = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 1024)
        assert reason is not None
        print("[OK] empty allowlist blocks all senders")


# ---------------------------------------------------------------------------
# check_metadata — audit events
# ---------------------------------------------------------------------------


class TestCheckMetadataAuditEvents:
    async def _gate_with_mock_audit(
        self, config: ImageAttachmentConfig | None = None
    ) -> tuple[ImageAttachmentGate, AsyncMock]:
        from openrattler.storage.audit import AuditLog

        mock_audit = AsyncMock(spec=AuditLog)
        gate = ImageAttachmentGate(config=config or _DEFAULT_CONFIG, audit=mock_audit)
        return gate, mock_audit

    async def test_disabled_channel_logs_correct_event(self) -> None:
        cfg = ImageAttachmentConfig(enabled=False)
        gate, audit = await self._gate_with_mock_audit(cfg)
        await gate.check_metadata("U_ANY", "slack", "image/jpeg", 100)
        audit.log.assert_called_once()
        event_arg = audit.log.call_args[0][0]
        assert event_arg.event == "image_attachment_disabled"
        print("[OK] disabled channel logs image_attachment_disabled")

    async def test_sender_rejected_logs_correct_event(self) -> None:
        gate, audit = await self._gate_with_mock_audit()
        await gate.check_metadata("U_BLOCKED", "slack", "image/jpeg", 100)
        audit.log.assert_called_once()
        event_arg = audit.log.call_args[0][0]
        assert event_arg.event == "image_sender_rejected"
        print("[OK] unknown sender logs image_sender_rejected")

    async def test_type_rejected_logs_correct_event(self) -> None:
        gate, audit = await self._gate_with_mock_audit()
        await gate.check_metadata("U_ALLOWED", "slack", "image/bmp", 100)
        audit.log.assert_called_once()
        event_arg = audit.log.call_args[0][0]
        assert event_arg.event == "image_type_rejected"
        print("[OK] disallowed type logs image_type_rejected")

    async def test_size_rejected_logs_correct_event(self) -> None:
        cfg = ImageAttachmentConfig(
            enabled=True, sender_allowlist=["U_ALLOWED"], max_size_bytes=100
        )
        gate, audit = await self._gate_with_mock_audit(cfg)
        await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 200)
        audit.log.assert_called_once()
        event_arg = audit.log.call_args[0][0]
        assert event_arg.event == "image_size_rejected"
        print("[OK] oversized image logs image_size_rejected")

    async def test_rate_limited_logs_correct_event(self) -> None:
        cfg = ImageAttachmentConfig(enabled=True, sender_allowlist=["U_ALLOWED"], max_per_hour=1)
        gate, audit = await self._gate_with_mock_audit(cfg)
        # First pass (within limit) — no rejection event.
        await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 100)
        assert audit.log.call_count == 0
        # Second attempt triggers rate limit.
        await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 100)
        audit.log.assert_called_once()
        event_arg = audit.log.call_args[0][0]
        assert event_arg.event == "image_rate_limited"
        print("[OK] rate-limited sender logs image_rate_limited")


# ---------------------------------------------------------------------------
# build_attachment
# ---------------------------------------------------------------------------


class TestBuildAttachment:
    async def test_returns_valid_message_attachment(self) -> None:
        gate = _make_gate()
        att = await gate.build_attachment("U_ALLOWED", "slack", "image/jpeg", _JPEG_BYTES)
        assert att.media_type == "image/jpeg"
        assert att.origin_channel == "slack"
        assert att.declared_by_sender == "U_ALLOWED"
        assert att.size_bytes == len(_JPEG_BYTES)
        print("[OK] build_attachment returns valid MessageAttachment")

    async def test_sha256_matches_raw_bytes(self) -> None:
        import hashlib

        gate = _make_gate()
        att = await gate.build_attachment("U_ALLOWED", "slack", "image/jpeg", _JPEG_BYTES)
        expected = hashlib.sha256(_JPEG_BYTES).hexdigest()
        assert att.sha256 == expected
        print("[OK] build_attachment sha256 matches raw bytes")

    async def test_data_is_valid_base64(self) -> None:
        import base64

        gate = _make_gate()
        att = await gate.build_attachment("U_ALLOWED", "slack", "image/png", _PNG_BYTES)
        decoded = base64.b64decode(att.data)
        assert decoded == _PNG_BYTES
        print("[OK] build_attachment data is valid base64")

    async def test_records_image_received_audit_event(self) -> None:
        from openrattler.storage.audit import AuditLog

        mock_audit = AsyncMock(spec=AuditLog)
        gate = ImageAttachmentGate(config=_DEFAULT_CONFIG, audit=mock_audit)
        att = await gate.build_attachment("U_ALLOWED", "slack", "image/jpeg", _JPEG_BYTES)
        mock_audit.log.assert_called_once()
        event_arg = mock_audit.log.call_args[0][0]
        assert event_arg.event == "image_received"
        assert event_arg.details["sha256"] == att.sha256
        assert event_arg.details["attachment_id"] == att.attachment_id
        print("[OK] build_attachment records image_received with sha256 and attachment_id")

    async def test_attachment_id_is_unique_per_call(self) -> None:
        gate = _make_gate()
        att1 = await gate.build_attachment("U_ALLOWED", "slack", "image/jpeg", _SMALL_IMAGE)
        att2 = await gate.build_attachment("U_ALLOWED", "slack", "image/jpeg", _SMALL_IMAGE)
        assert att1.attachment_id != att2.attachment_id
        print("[OK] build_attachment generates unique attachment_id per call")


# ---------------------------------------------------------------------------
# Rate limit boundary
# ---------------------------------------------------------------------------


class TestRateLimitBoundary:
    async def test_fifth_image_passes_sixth_is_rejected(self) -> None:
        cfg = ImageAttachmentConfig(
            enabled=True,
            sender_allowlist=["U_ALLOWED"],
            max_per_hour=5,
        )
        gate = _make_gate(cfg)
        # First 5 should all pass.
        for i in range(5):
            reason = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 100)
            assert reason is None, f"Expected pass on attempt {i + 1}, got: {reason}"
        # 6th should be rejected.
        reason = await gate.check_metadata("U_ALLOWED", "slack", "image/jpeg", 100)
        assert reason is not None
        print("[OK] 5th image passes, 6th is rejected")

    async def test_different_senders_have_independent_limits(self) -> None:
        cfg = ImageAttachmentConfig(
            enabled=True,
            sender_allowlist=["U_A", "U_B"],
            max_per_hour=1,
        )
        gate = _make_gate(cfg)
        # First sender hits their limit.
        assert await gate.check_metadata("U_A", "slack", "image/jpeg", 100) is None
        assert await gate.check_metadata("U_A", "slack", "image/jpeg", 100) is not None
        # Second sender is unaffected.
        assert await gate.check_metadata("U_B", "slack", "image/jpeg", 100) is None
        print("[OK] rate limits are per-sender, not shared")
