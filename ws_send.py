"""One-shot WebSocket client — sends a message, waits for a response, prints it.

Usage:
    python ws_send.py "your message here"
"""
from __future__ import annotations

import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone

import aiohttp

_DEV_SECRET = "dev-secret-changeme"
_WS_URL = "ws://127.0.0.1:8765/ws"
_CHANNEL_ID = "channel:ws:client"
_AGENT_ID = "agent:main:main"
_SESSION_KEY = "agent:main:main"
_PROTOCOL_VERSION = "1"


def _generate_token(secret: str, channel_id: str) -> str:
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


async def main(message: str, timeout: int = 120) -> None:
    token = _generate_token(_DEV_SECRET, _CHANNEL_ID)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Protocol-Version": _PROTOCOL_VERSION,
    }

    print(f"[ws_send] Connecting to {_WS_URL} ...")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.ws_connect(_WS_URL, headers=headers) as ws:
                print(f"[ws_send] Connected. Sending: {message[:80]!r}")
                await ws.send_str(_build_message(message))

                print(f"[ws_send] Waiting for response (timeout={timeout}s)...")
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=timeout)
                except asyncio.TimeoutError:
                    print(f"[ws_send] TIMEOUT after {timeout}s — no response received.")
                    sys.exit(2)

                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    print(f"[ws_send] Raw response type: {data.get('type')}")
                    if data.get("type") == "error":
                        print(f"\n[ERROR RESPONSE]\n{json.dumps(data.get('params', {}), indent=2)}")
                    else:
                        content = data.get("params", {}).get("content", "(empty response)")
                        print(f"\n--- CORVUS RESPONSE ---\n{content}\n--- END RESPONSE ---")
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    print(f"[ws_send] Connection closed unexpectedly: {msg.type}")
                    sys.exit(1)

        except aiohttp.ClientConnectorError as e:
            print(f"[ws_send] ERROR — Could not connect: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ws_send.py 'message'", file=sys.stderr)
        sys.exit(1)
    msg = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    asyncio.run(main(msg, timeout))
