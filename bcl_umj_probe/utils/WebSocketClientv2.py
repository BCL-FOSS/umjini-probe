import logging
import aiohttp
from aiohttp import WSMsgType, ClientWSTimeout, WSServerHandshakeError
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class WebSocketClient:
    """
    Async context manager for opening a websocket and sending an `access_token`
    authentication cookie in the handshake via the Cookie header. Adds an Origin
    header derived from the URL to mirror browser behavior (some servers/checks expect it).
    """

    def __init__(self, url: str, access_token: str, *, timeout: float = 10.0, cookie_name: str = "access_token", debug_on_fail: bool = False):
        self.url = url
        self.access_token = access_token
        self.cookie_name = cookie_name
        self.timeout = timeout
        self.session: aiohttp.ClientSession | None = None
        self.ws: aiohttp.ClientWebSocketResponse | None = None
        self.debug_on_fail = debug_on_fail

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        parsed = urlparse(self.url)
        origin = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}"

        headers = {
            "Cookie": f"{self.cookie_name}={self.access_token}",
            "Origin": origin,
            # Add a User-Agent to be polite and closer to a browser handshake
            "User-Agent": "umj-probe/1.0 (+https://example.org)"
        }

        # Build a proper ClientWSTimeout to avoid the deprecated float usage.
        ws_timeout = ClientWSTimeout() if self.timeout is not None else None

        try:
            # Pass the headers and a ClientWSTimeout instance (if provided)
            if ws_timeout is None:
                self.ws = await self.session.ws_connect(self.url, headers=headers)
            else:
                self.ws = await self.session.ws_connect(self.url, headers=headers, timeout=ws_timeout)

        except aiohttp.WSServerHandshakeError as exc:
            # Handshake failed (non-101). Log details and optionally fetch the HTTP body for debugging.
            logger.error(f"WebSocket handshake failed: {getattr(exc, 'status', 'N/A')} {exc}")
            if self.debug_on_fail:
                try:
                    # Try a plain GET with same headers to capture response body (useful for 429/500 debugging)
                    async with self.session.get(self.url.replace('wss://', 'https://').replace('ws://', 'http://'), headers=headers, timeout=10.0) as r:
                        text = await r.text()
                        logger.debug(f"HTTP GET to ws url returned {r.status}: {text[:1000]}")
                except Exception as e:
                    logger.debug(f"Failed debug GET: {e}")
            # Ensure session closed to avoid resource leaks
            try:
                await self.session.close()
            except Exception:
                pass
            raise

        except Exception:
            # Any other error: ensure session closed, re-raise
            try:
                await self.session.close()
            except Exception:
                pass
            raise

        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.ws is not None:
            try:
                await self.ws.close()
            except Exception:
                pass
            finally:
                self.ws = None

        if self.session is not None:
            try:
                await self.session.close()
            except Exception:
                pass
            finally:
                self.session = None

    async def send(self, text: str):
        if self.ws is None:
            raise RuntimeError("WebSocket is not connected")
        await self.ws.send_str(text)

    async def recv(self):
        if self.ws is None:
            raise RuntimeError("WebSocket is not connected")

        msg = await self.ws.receive()
        if msg.type == WSMsgType.TEXT:
            return msg.data
        if msg.type == WSMsgType.BINARY:
            return msg.data
        if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSED):
            raise ConnectionError("WebSocket closed")
        if msg.type == WSMsgType.ERROR:
            # msg.data may be an exception
            raise msg.data
        return msg.data