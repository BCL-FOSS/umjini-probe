import asyncio
import aiohttp
from urllib.parse import urlparse

class WebSocketClient:
    def __init__(self, url: str, access_token: str, *, timeout: int = 10):
        self.url = url
        self.access_token = access_token
        self.timeout = timeout
        self.session = None
        self.ws = None

    async def __aenter__(self):
        # Create a session and set the Cookie header explicitly on the websocket handshake.
        self.session = aiohttp.ClientSession()
        parsed = urlparse(self.url)
        origin = f"{'https' if parsed.scheme == 'wss' else 'http'}://{parsed.netloc}"

        headers = {
            "Cookie": f"access_token={self.access_token}",
            "Origin": origin,
            # Add a User-Agent to be polite and closer to a browser handshake
            "User-Agent": "umj-probe/1.0 (+https://example.org)"
        }

        try:
            self.ws = await self.session.ws_connect(self.url, headers=headers)
        except Exception:
            # Make sure we don't leak the session if handshake fails
            try:
                await self.session.close()
            except Exception:
                pass
            raise

        return self

    async def __aexit__(self, exc_type, exc, tb):
        # Close ws first, then session
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

    """
     async def __aenter__(self):
        # create a session and set the cookie so it's sent on the ws handshake
        self.session = aiohttp.ClientSession()
        self.session.cookie_jar.update_cookies({"access_token": self.access_token})
        self.ws = await self.session.ws_connect(self.url, timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.ws is not None:
            await self.ws.close()
        if self.session is not None:
            await self.session.close()
    """
    async def send(self, text: str):
        await self.ws.send_str(text)

    async def recv(self):
        msg = await self.ws.receive()
        return msg.data