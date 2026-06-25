"""
异步验证器适配器 - 支持 AsyncDatabase

核心改进:
1. 完全异步化,消除阻塞
2. 使用 asyncio.Queue
3. 批量数据库操作
4. 改进的错误处理
"""

import asyncio
from typing import Optional
from loguru import logger

from validator import (
    validate_key_async,
    CircuitBreaker,
    MAX_CONCURRENCY
)
from async_database import AsyncDatabase
from database import LeakedKey, KeyStatus


def _to_leaked_key(item) -> LeakedKey:
    """Normalize scanner queue items to the DB model used by the validator."""
    if isinstance(item, LeakedKey):
        return item
    return LeakedKey(
        platform=getattr(item, "platform", ""),
        api_key=getattr(item, "api_key", ""),
        base_url=getattr(item, "base_url", ""),
        source_url=getattr(item, "source_url", ""),
    )


def _should_persist(status: KeyStatus) -> bool:
    """Only keep keys with operator value; invalid candidates stay out of DB."""
    return status in {
        KeyStatus.VALID,
        KeyStatus.QUOTA_EXCEEDED,
        KeyStatus.CONNECTION_ERROR,
        KeyStatus.UNVERIFIED,
    }


def _stat_name(status: KeyStatus) -> Optional[str]:
    if status == KeyStatus.INVALID:
        return "invalid_keys"
    if status == KeyStatus.QUOTA_EXCEEDED:
        return "quota_exceeded"
    if status == KeyStatus.CONNECTION_ERROR:
        return "connection_errors"
    if status == KeyStatus.UNVERIFIED:
        return "unverified_keys"
    return "error_keys"


async def async_validator_worker(
    result_queue: asyncio.Queue,
    async_db: AsyncDatabase,
    stop_event,
    dashboard=None,
    worker_id: int = 0
):
    """
    异步验证器工作线程

    Args:
        result_queue: asyncio.Queue 结果队列
        async_db: AsyncDatabase 异步数据库
        stop_event: threading.Event 停止信号
        dashboard: Dashboard UI实例
        worker_id: 工作线程ID
    """
    circuit_breaker = CircuitBreaker()
    processed_count = 0

    logger.info(f"[Validator-{worker_id}] 异步验证器启动")

    try:
        while not stop_event.is_set():
            try:
                # 使用 asyncio.wait_for 避免永久阻塞
                key = await asyncio.wait_for(
                    result_queue.get(),
                    timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"[Validator-{worker_id}] 队列读取错误: {e}")
                continue

            try:
                key = _to_leaked_key(key)
                if not key.api_key:
                    continue

                # 已入库说明之前验证后被保留过，跳过重复候选。
                if await async_db.key_exists(key.api_key):
                    processed_count += 1
                    if dashboard:
                        dashboard.increment_stat("skipped_existing")
                    logger.debug(f"[Validator-{worker_id}] Key 已存在,跳过: {key.api_key[:20]}...")
                    continue

                # 先验证；只有有效/配额耗尽/连接异常/无法验证等有保留价值的结果才入库。
                status, balance, model_tier, rpm, is_high_value = await validate_key_async(
                    key.platform,
                    key.api_key,
                    key.base_url,
                    circuit_breaker=circuit_breaker
                )

                if _should_persist(status):
                    key.status = status.value
                    key.balance = balance
                    key.model_tier = model_tier
                    key.rpm = rpm
                    key.is_high_value = is_high_value
                    await async_db.insert_key_now(key)
                    await async_db.update_key_status(
                        key.api_key,
                        status,
                        balance,
                        model_tier,
                        rpm,
                        is_high_value
                    )

                processed_count += 1

                # 更新 UI / 统计。invalid 不入库，但要计入已验证结果。
                if dashboard:
                    stat_name = _stat_name(status)
                    if stat_name:
                        dashboard.increment_stat(stat_name)

                    if status == KeyStatus.VALID:
                        dashboard.add_valid_key(
                            key.platform,
                            key.api_key[:10] + "..." + key.api_key[-4:] if len(key.api_key) > 18 else key.api_key,
                            balance,
                            key.source_url,
                            is_high_value,
                        )
                        dashboard.add_log(
                            f"[✓] {key.platform} | {balance} | {key.api_key[:20]}...",
                            "SUCCESS"
                        )
                    elif status == KeyStatus.QUOTA_EXCEEDED:
                        dashboard.add_log(
                            f"[💰] {key.platform} | 配额耗尽 | {key.api_key[:20]}...",
                            "WARNING"
                        )
                    elif status == KeyStatus.INVALID:
                        dashboard.add_log(
                            f"[×] {key.platform} | 无效，未入库 | {key.api_key[:20]}...",
                            "DEBUG"
                        )

                # 每处理 10 个 Key 输出一次统计
                if processed_count % 10 == 0:
                    logger.info(f"[Validator-{worker_id}] 已处理 {processed_count} 个 Key")

            except Exception as e:
                logger.error(f"[Validator-{worker_id}] 验证异常: {e}")
                if dashboard:
                    dashboard.increment_stat("error_keys")
                    dashboard.add_log(f"[✗] 验证错误: {str(e)[:50]}", "ERROR")

    except asyncio.CancelledError:
        logger.info(f"[Validator-{worker_id}] 收到取消信号")
    finally:
        logger.info(f"[Validator-{worker_id}] 验证器停止,共处理 {processed_count} 个 Key")


def start_async_validators(
    result_queue: asyncio.Queue,
    async_db: AsyncDatabase,
    stop_event,
    dashboard=None,
    num_workers: int = 2
):
    """
    启动异步验证器

    Args:
        result_queue: asyncio.Queue
        async_db: AsyncDatabase
        stop_event: threading.Event
        dashboard: Dashboard
        num_workers: 工作线程数

    Returns:
        List[asyncio.Task]
    """
    import threading

    tasks = []

    def run_async_workers():
        """在新线程中运行异步工作器"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # 创建工作任务
        worker_tasks = []
        for i in range(num_workers):
            task = loop.create_task(
                async_validator_worker(
                    result_queue,
                    async_db,
                    stop_event,
                    dashboard,
                    worker_id=i
                )
            )
            worker_tasks.append(task)

        # 运行直到停止
        try:
            loop.run_until_complete(asyncio.gather(*worker_tasks))
        except Exception as e:
            logger.error(f"验证器异常: {e}")
        finally:
            loop.close()

    # 启动线程
    thread = threading.Thread(target=run_async_workers, daemon=True)
    thread.start()

    return [thread]
