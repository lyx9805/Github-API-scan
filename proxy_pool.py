"""
代理池模块 - 多代理轮换、健康检查与动态代理源支持
"""

import asyncio
import aiohttp
import random
from typing import List, Optional, Dict
from dataclasses import dataclass
from datetime import datetime
from loguru import logger


@dataclass
class ProxyInfo:
    """代理信息"""
    url: str
    protocol: str = "http"
    fail_count: int = 0
    success_count: int = 0
    last_check: Optional[datetime] = None
    is_healthy: bool = True
    health_score: float = 100.0


class ProxyPool:
    """代理池管理器"""

    def __init__(
        self,
        proxies: Optional[List[str]] = None,
        dynamic_source_url: str = "",
        max_fail_count: int = 3,
        health_check_interval: int = 300,
    ):
        self.proxies: List[ProxyInfo] = []
        self.dynamic_source_url = (dynamic_source_url or "").strip()
        self.max_fail_count = max_fail_count
        self.health_check_interval = health_check_interval
        self._index = 0
        self._lock = asyncio.Lock()

        for proxy in proxies or []:
            self.add_proxy(proxy)

    def set_dynamic_source(self, source_url: str):
        self.dynamic_source_url = (source_url or "").strip()

    def add_proxy(self, proxy_url: str):
        proxy_url = (proxy_url or "").strip()
        if not proxy_url:
            return
        if not proxy_url.startswith(("http://", "https://", "socks5://")):
            proxy_url = "http://" + proxy_url
        if any(existing.url == proxy_url for existing in self.proxies):
            return
        protocol = "socks5" if proxy_url.startswith("socks5") else "http"
        self.proxies.append(ProxyInfo(url=proxy_url, protocol=protocol))
        logger.info(f"Added proxy: {proxy_url[:60]}")

    def remove_proxy(self, proxy_url: str):
        self.proxies = [proxy for proxy in self.proxies if proxy.url != proxy_url]

    def clear_proxies(self):
        self.proxies = []
        self._index = 0

    def _recalculate_health(self, proxy: ProxyInfo):
        proxy.health_score = max(0.0, min(100.0, 100.0 + proxy.success_count * 5 - proxy.fail_count * 20))
        proxy.is_healthy = proxy.fail_count < self.max_fail_count and proxy.health_score > 0

    async def fetch_dynamic_proxy(self) -> Optional[str]:
        source_url = self.dynamic_source_url
        if not source_url:
            return None
        timeout = aiohttp.ClientTimeout(total=15)
        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
                async with session.get(source_url) as resp:
                    if resp.status != 200:
                        logger.warning(f"Dynamic proxy source returned {resp.status}")
                        return None
                    content = (await resp.text()).strip()
        except Exception as exc:
            logger.warning(f"Dynamic proxy source request failed: {type(exc).__name__}: {exc}")
            return None

        for line in content.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            self.add_proxy(candidate)
            return self.proxies[-1].url
        return None

    async def get_proxy(self) -> Optional[str]:
        async with self._lock:
            healthy = [proxy for proxy in self.proxies if proxy.is_healthy]
            if not healthy and self.dynamic_source_url:
                fetched = await self.fetch_dynamic_proxy()
                if fetched:
                    healthy = [proxy for proxy in self.proxies if proxy.is_healthy]
            if not healthy:
                return None
            healthy.sort(key=lambda proxy: (proxy.health_score, proxy.success_count, -proxy.fail_count), reverse=True)
            self._index = (self._index + 1) % len(healthy)
            return healthy[self._index].url

    async def refresh_proxy(self) -> Optional[str]:
        async with self._lock:
            return await self.fetch_dynamic_proxy()

    async def get_random_proxy(self) -> Optional[str]:
        healthy = [proxy for proxy in self.proxies if proxy.is_healthy]
        if not healthy and self.dynamic_source_url:
            fetched = await self.fetch_dynamic_proxy()
            if fetched:
                healthy = [proxy for proxy in self.proxies if proxy.is_healthy]
        if not healthy:
            return None
        return random.choice(healthy).url

    async def report_success(self, proxy_url: str):
        for proxy in self.proxies:
            if proxy.url == proxy_url:
                proxy.success_count += 1
                proxy.fail_count = 0
                proxy.last_check = datetime.now()
                self._recalculate_health(proxy)
                break

    async def report_failure(self, proxy_url: str):
        for proxy in self.proxies:
            if proxy.url == proxy_url:
                proxy.fail_count += 1
                proxy.last_check = datetime.now()
                self._recalculate_health(proxy)
                if not proxy.is_healthy:
                    logger.warning(f"Proxy marked unhealthy: {proxy_url[:60]}")
                break

    async def health_check(self, test_url: str = "https://api.openai.com/v1/models"):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10), trust_env=True) as session:
            for proxy in self.proxies:
                try:
                    async with session.get(test_url, proxy=proxy.url, headers={"Authorization": "Bearer test"}) as resp:
                        if resp.status in {200, 401, 403, 429}:
                            proxy.is_healthy = True
                            proxy.fail_count = 0
                        else:
                            proxy.fail_count += 1
                except Exception:
                    proxy.fail_count += 1

                if proxy.fail_count >= self.max_fail_count:
                    proxy.is_healthy = False
                proxy.last_check = datetime.now()
                self._recalculate_health(proxy)

    def get_stats(self) -> Dict:
        healthy = sum(1 for proxy in self.proxies if proxy.is_healthy)
        return {
            "total": len(self.proxies),
            "healthy": healthy,
            "unhealthy": len(self.proxies) - healthy,
            "dynamic_source_url": self.dynamic_source_url,
            "proxies": [
                {
                    "url": proxy.url[:60] + ("..." if len(proxy.url) > 60 else ""),
                    "healthy": proxy.is_healthy,
                    "success": proxy.success_count,
                    "fail": proxy.fail_count,
                    "health_score": round(proxy.health_score, 1),
                    "last_check": proxy.last_check.isoformat() if proxy.last_check else None,
                }
                for proxy in sorted(self.proxies, key=lambda item: (item.health_score, item.success_count), reverse=True)
            ],
        }

    @property
    def has_healthy_proxy(self) -> bool:
        return any(proxy.is_healthy for proxy in self.proxies)


_proxy_pool: Optional[ProxyPool] = None


def init_proxy_pool(proxies: List[str], dynamic_source_url: str = "") -> ProxyPool:
    global _proxy_pool
    _proxy_pool = ProxyPool(proxies, dynamic_source_url=dynamic_source_url)
    return _proxy_pool


def get_proxy_pool() -> Optional[ProxyPool]:
    return _proxy_pool


async def get_next_proxy() -> Optional[str]:
    if _proxy_pool:
        return await _proxy_pool.get_proxy()
    return None
