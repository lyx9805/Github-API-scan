#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Redis 持久化缓存管理器 — v2.2+ 扩展

与 CacheManager 保持相同的公开 API，但将三层缓存存入 Redis：

  - L1 (validation result):    cache:v1:<key_hash>  → hash, TTL=1h
  - L2 (domain health):        cache:domain:<domain> → hash, TTL=30min
  - L3 (key fingerprint):      cache:fp:<sha16>      → string, TTL=24h

当 redis_url 为空时降级为纯内存 CacheManager，零配置即可运行。
"""

import asyncio
import hashlib
import json
import time
from typing import Any, Dict, Optional
from dataclasses import dataclass

from loguru import logger

from cache_manager import CacheConfig, DomainHealth, DomainHealthEntry, CacheManager


# ============================================================================
#                          Redis 版本常量
# ============================================================================

_KEY_PREFIX_VALIDATION = "cache:v1"
_KEY_PREFIX_DOMAIN = "cache:domain"
_KEY_PREFIX_FINGERPRINT = "cache:fp"


@dataclass
class RedisSettings:
    url: str = ""
    socket_timeout: float = 5.0
    socket_connect_timeout: float = 3.0
    retry_on_timeout: bool = True
    max_connections: int = 20
    # 连接断开时是否降级为内存模式
    fallback_to_memory: bool = True


# ============================================================================
#                          RedisCacheManager
# ============================================================================

class RedisCacheManager(CacheManager):
    """Redis 持久化缓存管理器 — 继承 CacheManager 接口，存储层改用 Redis。

    未命中 Redis 时自动走父类的内存兜底（L1/L2/L3 仍保留为二级缓存）。
    """

    def __init__(self, config: Optional[CacheConfig] = None,
                 redis_settings: Optional[RedisSettings] = None):
        super().__init__(config)
        self._redis_settings = redis_settings or RedisSettings()
        self._redis = None
        self._redis_available = False

    # ========================================================================
    #  生命周期
    # ========================================================================

    async def start(self):
        """连接 Redis；失败时降级为内存模式。"""
        await super().start()  # 启动清理任务（内存兜底用）

        if not self._redis_settings.url:
            logger.info("Redis 未配置，使用纯内存缓存")
            return

        try:
            from redis.asyncio import Redis as AsyncRedis, ConnectionPool

            pool = ConnectionPool.from_url(
                self._redis_settings.url,
                socket_timeout=self._redis_settings.socket_timeout,
                socket_connect_timeout=self._redis_settings.socket_connect_timeout,
                retry_on_timeout=self._redis_settings.retry_on_timeout,
                max_connections=self._redis_settings.max_connections,
                decode_responses=True,
            )
            self._redis = AsyncRedis(connection_pool=pool)
            await self._redis.ping()
            self._redis_available = True
            logger.info(f"Redis 缓存已连接 ({self._redis_settings.url})")
        except Exception as exc:
            self._redis = None
            self._redis_available = False
            msg = f"Redis 连接失败: {exc}"
            if self._redis_settings.fallback_to_memory:
                logger.warning(f"{msg} — 降级为内存缓存")
            else:
                logger.error(msg)
                raise

    async def stop(self):
        """关闭 Redis 连接。"""
        await super().stop()
        if self._redis:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None
            self._redis_available = False
            logger.info("Redis 连接已关闭")

    # ========================================================================
    #  工具方法
    # ========================================================================

    @staticmethod
    def _make_key_hash(api_key: str, base_url: str) -> str:
        raw = f"{api_key}::{base_url}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _make_fingerprint(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]

    def _extract_domain(self, url: str) -> str:
        from urllib.parse import urlparse
        try:
            return urlparse(url).netloc.lower().split(":")[0]
        except Exception:
            return ""

    # ========================================================================
    #  L1 — 验证结果缓存
    # ========================================================================

    async def get_validation_result(self, api_key: str,
                                    base_url: str) -> Optional[Dict]:
        # 1) 尝试 Redis
        if self._redis_available:
            key = f"{_KEY_PREFIX_VALIDATION}:{self._make_key_hash(api_key, base_url)}"
            try:
                raw = await self._redis.get(key)
                if raw is not None:
                    self._stats["validation_hits"] += 1
                    val = json.loads(raw)
                    # 同步写入内存供快速二次访问
                    self._validation_cache[key] = self._CacheEntryAdapter(val)
                    return val
            except Exception:
                pass  # 降级到内存

        self._stats["validation_misses"] += 1
        # 2) 内存兜底
        return await super().get_validation_result(api_key, base_url)

    async def set_validation_result(self, api_key: str, base_url: str,
                                    result: Dict):
        # 1) 写入内存
        await super().set_validation_result(api_key, base_url, result)

        # 2) 写入 Redis
        if self._redis_available:
            key = f"{_KEY_PREFIX_VALIDATION}:{self._make_key_hash(api_key, base_url)}"
            try:
                await self._redis.setex(
                    key,
                    int(self.config.validation_ttl),
                    json.dumps(result, default=str),
                )
            except Exception:
                pass

    # ========================================================================
    #  L2 — 域名健康追踪
    # ========================================================================

    async def get_domain_health(self, url: str) -> Optional[DomainHealth]:
        if self._redis_available:
            domain = self._extract_domain(url)
            if not domain:
                return None
            key = f"{_KEY_PREFIX_DOMAIN}:{domain}"
            try:
                raw = await self._redis.hgetall(key)
                if raw:
                    health = DomainHealth(raw.get("health", DomainHealth.HEALTHY.value))
                    entry = DomainHealthEntry(
                        domain=domain,
                        health=health,
                        failure_count=int(raw.get("failure_count", 0)),
                        success_count=int(raw.get("success_count", 0)),
                        last_check=float(raw.get("last_check", time.time())),
                    )
                    self._domain_health[domain] = entry
                    self._stats["domain_health_hits"] += 1
                    return health
            except Exception:
                pass

        return await super().get_domain_health(url)

    async def record_domain_success(self, url: str):
        await super().record_domain_success(url)
        if not self._redis_available:
            return
        domain = self._extract_domain(url)
        if not domain:
            return
        key = f"{_KEY_PREFIX_DOMAIN}:{domain}"
        try:
            await self._redis.hincrby(key, "success_count", 1)
            await self._redis.hset(key, "health", DomainHealth.HEALTHY.value)
            await self._redis.hset(key, "last_check", time.time())
            await self._redis.expire(key, int(self.config.domain_health_ttl))
        except Exception:
            pass

    async def record_domain_failure(self, url: str):
        await super().record_domain_failure(url)
        if not self._redis_available:
            return
        domain = self._extract_domain(url)
        if not domain:
            return
        key = f"{_KEY_PREFIX_DOMAIN}:{domain}"
        try:
            new_count = await self._redis.hincrby(key, "failure_count", 1)
            await self._redis.hset(key, "last_check", time.time())
            # 同步健康状态
            if new_count >= 10:
                health = DomainHealth.DEAD.value
            elif new_count >= 5:
                health = DomainHealth.UNHEALTHY.value
            elif new_count >= 2:
                health = DomainHealth.DEGRADED.value
            else:
                health = DomainHealth.HEALTHY.value
            await self._redis.hset(key, "health", health)
            await self._redis.expire(key, int(self.config.domain_health_ttl))
        except Exception:
            pass

    # ========================================================================
    #  L3 — Key 指纹去重
    # ========================================================================

    async def has_key_fingerprint(self, api_key: str) -> bool:
        if self._redis_available:
            fp = self._make_fingerprint(api_key)
            key = f"{_KEY_PREFIX_FINGERPRINT}:{fp}"
            try:
                exists = await self._redis.exists(key)
                if exists:
                    self._stats["fingerprint_hits"] += 1
                    # 同步到内存
                    self._key_fingerprints.add(fp)
                    return True
            except Exception:
                pass

        return await super().has_key_fingerprint(api_key)

    async def add_key_fingerprint(self, api_key: str):
        await super().add_key_fingerprint(api_key)
        if self._redis_available:
            fp = self._make_fingerprint(api_key)
            key = f"{_KEY_PREFIX_FINGERPRINT}:{fp}"
            try:
                await self._redis.setex(
                    key,
                    int(self.config.key_fingerprint_ttl),
                    "1",
                )
            except Exception:
                pass

    # ========================================================================
    #  管理接口
    # ========================================================================

    async def clear(self):
        await super().clear()
        if self._redis_available:
            try:
                cursor = 0
                while True:
                    cursor, keys = await self._redis.scan(
                        cursor, match=f"{_KEY_PREFIX_VALIDATION}:*", count=200
                    )
                    if keys:
                        await self._redis.delete(*keys)
                    if cursor == 0:
                        break
                cursor = 0
                while True:
                    cursor, keys = await self._redis.scan(
                        cursor, match=f"{_KEY_PREFIX_DOMAIN}:*", count=200
                    )
                    if keys:
                        await self._redis.delete(*keys)
                    if cursor == 0:
                        break
                cursor = 0
                while True:
                    cursor, keys = await self._redis.scan(
                        cursor, match=f"{_KEY_PREFIX_FINGERPRINT}:*", count=200
                    )
                    if keys:
                        await self._redis.delete(*keys)
                    if cursor == 0:
                        break
                logger.info("Redis 缓存已清空")
            except Exception as exc:
                logger.warning(f"Redis 清空失败: {exc}")

    async def clear_validation_cache(self):
        await super().clear_validation_cache()
        if self._redis_available:
            try:
                cursor = 0
                while True:
                    cursor, keys = await self._redis.scan(
                        cursor, match=f"{_KEY_PREFIX_VALIDATION}:*", count=200
                    )
                    if keys:
                        await self._redis.delete(*keys)
                    if cursor == 0:
                        break
                logger.info("Redis 验证缓存已清空")
            except Exception as exc:
                logger.warning(f"Redis 清空验证缓存失败: {exc}")


# ============================================================================
#  辅助 — 把从 Redis 读回的 dict 包装成 CacheEntry 的形态
# ============================================================================

class _CacheEntryAdapter:
    """让从 Redis 反序列化的结果可以暂存在父类 L1 缓存中。"""
    def __init__(self, value: Any):
        self.value = value
        self.timestamp = time.time()
        self.ttl = 3600.0
        self.hit_count = 1

    def is_expired(self) -> bool:
        return False  # 让清理循环决定

    def touch(self):
        self.hit_count += 1
