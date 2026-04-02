"""Interactive WebSocket client for OpenRattler gateway.

Usage:
    python ws_client.py

Generates a valid Bearer token using the dev secret, connects to the gateway,
and lets you chat interactively. Type /quit to exit.
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone

import aiohttp

# Must match _DEV_WS_SECRET in startup.py
_DEV_SECRET = "dev-secret-changeme"
_WS_URL = "ws://127.0.0.1:8765/ws"
_CHANNEL_ID = "channel:ws:client"
_AGENT_ID = "agent:main:main"
_SESSION_KEY = "agent:main:main"
_PROTOCOL_VERSION = "1"


def _generate_token(secret: str, channel_id: str) -> str:
    """Generate a dev HMAC-SHA256 Bearer token (mirrors TokenAuth.generate_token)."""
    import base64
    import hashlib
    import hmac

    _SEP = "."
    payload = json.dumps(
        {"channel_id": channel_id, "iat": int(datetime.now(timezone.utc).timestamp())}
    )
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode()
    sig = hmac.new(secret.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}{_SEP}{sig}"


def _build_message(content: str) -> str:
    return json.dumps(
        {
            "message_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "from_agent": _CHANNEL_ID,
            "to_agent": _AGENT_ID,
            "session_key": _SESSION_KEY,
            "type": "request",
            "trust_level": "main",
            "trace_id": str(uuid.uuid4()),
            "operation": "chat",
            "params": {"content": content},
            "metadata": {},
            "requires_approval": False,
        }
    )


async def main() -> None:
    token = _generate_token(_DEV_SECRET, _CHANNEL_ID)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Protocol-Version": _PROTOCOL_VERSION,
    }

    print(f"Connecting to {_WS_URL} ...")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.ws_connect(_WS_URL, headers=headers) as ws:
                print("Connected! Type your message and press Enter. /quit to exit.\n")

                while True:
                    try:
                        user_input = await asyncio.get_event_loop().run_in_executor(
                            None, lambda: input("You: ")
                        )
                    except EOFError:
                        break

                    if user_input.strip().lower() in ("/quit", "/exit"):
                        break
                    if not user_input.strip():
                        continue

                    await ws.send_str(_build_message(user_input))

                    msg = await ws.receive()
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        data = json.loads(msg.data)
                        if data.get("type") == "error":
                            text = f"[ERROR] {data.get('error', {})}"
                        else:
                            text = data.get("params", {}).get("content", "(empty response)")
                        print(f"\nAssistant: {text}\n")
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        print(f"[Connection closed: {msg.type}]")
                        break

        except aiohttp.ClientConnectorError as e:
            print(f"[ERROR] Could not connect: {e}", file=sys.stderr)
            sys.exit(1)

    print("Goodbye!")


if __name__ == "__main__":
    asyncio.run(main())
