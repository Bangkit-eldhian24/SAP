"""
SAPT HTTP Utilities — Shared aiohttp session and request helpers.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import aiohttp

from sapt.core.logger import get_logger


class HTTPClient:
    """Shared HTTP client with rate limiting and retry logic."""

    def __init__(
        self,
        rate_limit: int = 100,
        timeout: int = 10,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        self.rate_limit = rate_limit
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent = user_agent
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(rate_limit)

    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
            )
        return self._session

    async def get(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        async with self._semaphore:
            session = await self.get_session()
            try:
                return await session.get(url, **kwargs)
            except Exception as e:
                get_logger().debug(f"HTTP GET failed for {url}: {e}")
                return None

    async def post(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        async with self._semaphore:
            session = await self.get_session()
            try:
                return await session.post(url, **kwargs)
            except Exception as e:
                get_logger().debug(f"HTTP POST failed for {url}: {e}")
                return None

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
