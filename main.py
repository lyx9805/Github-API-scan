#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Secret Scanner Pro — 统一入口

功能概要：
  v2.2 — 智能缓存 (3层缓存架构、批量验证、域名健康追踪)
  v2.1 — 连接池管理、智能重试、动态队列、性能监控
  v2.0 — 异步数据库、加密导出、外部配置

用法：
  python main.py                          # 启动扫描（默认 v2.2 全部特性）
  python main.py --no-cache               # 禁用缓存（回退 v2.1 行为）
  python main.py --no-monitor             # 禁用性能监控
  python main.py --monitor                # 实时监控+推送模式
  python main.py --stats                  # 数据库统计
  python main.py --export valid.txt       # 导出有效 Key
  python main.py --export-csv keys.csv    # 导出 CSV
"""

import sys
import signal
import asyncio
import threading
from pathlib import Path
import time
import argparse
import csv
from datetime import datetime
from typing import Optional

from config import config
from database import Database, KeyStatus
from async_database import AsyncDatabase, try_enable_uvloop
from scanner import start_scanner
from ui import Dashboard
from source_pastebin import start_pastebin_scanner
from source_gist import start_gist_scanner
from source_searchcode import start_searchcode_scanner
from source_gitlab import start_gitlab_scanner
from source_realtime import start_realtime_scanner
from source_sourcegraph import start_sourcegraph_scanner
from source_git_clone import start_git_clone_scanner

# v2.1 优化模块
from performance_monitor import get_monitor
from connection_pool import get_connection_pool, close_connection_pool
from queue_manager import create_queue

# v2.2 新增模块
from cache_manager import get_cache_manager, close_cache_manager, CacheConfig
from batch_validator import BatchConfig

from loguru import logger


# ============================================================================
#                          配置验证
# ============================================================================

class ConfigValidator:
    """配置验证器"""

    @staticmethod
    def validate() -> tuple[bool, list[str]]:
        """验证配置有效性"""
        errors = []

        if not config.github_tokens or not any(config.github_tokens):
            errors.append("未配置 GitHub Tokens")

        if not config.db_path:
            errors.append("数据库路径未配置")

        if config.proxy_url:
            if not config.proxy_url.startswith(('http://', 'https://', 'socks5://')):
                errors.append(f"代理地址格式错误: {config.proxy_url}")

        return len(errors) == 0, errors


# ============================================================================
#                          SecretScanner — 统一扫描器
# ============================================================================

class SecretScanner:
    """密钥扫描系统 — 统一版本（v2.2 + v2.1 + v2.0）"""

    def __init__(self, enable_pastebin: bool = False, enable_gist: bool = False,
                 enable_searchcode: bool = False, enable_gitlab: bool = False,
                 enable_realtime: bool = False, enable_sourcegraph: bool = False,
                 enable_git_clone: bool = False,
                 git_clone_dir: str = '',
                 pastebin_api_key: str = "",
                 enable_performance_monitor: bool = True,
                 enable_cache: bool = True,
                 redis_url: str = '',
                 monitor_mode: bool = False):
        self.stop_event = threading.Event()

        # 队列
        self.result_queue = None
        self.use_dynamic_queue = True

        # 数据库
        self.async_db: Optional[AsyncDatabase] = None
        self.db = Database(config.db_path)

        self.dashboard = Dashboard()

        # 性能监控 (v2.1)
        self.performance_monitor = None
        self.enable_performance_monitor = enable_performance_monitor

        # 缓存 (v2.2)
        self.cache_manager = None
        self.enable_cache = enable_cache
        self.redis_url = redis_url

        # 线程
        self.scanner_thread = None
        self.validator_threads = []
        self.pastebin_thread = None
        self.gist_thread = None
        self.searchcode_thread = None
        self.gitlab_thread = None
        self.realtime_thread = None
        self.sourcegraph_thread = None
        self.git_clone_thread = None

        # 扫描源开关
        self.enable_pastebin = enable_pastebin
        self.enable_gist = enable_gist
        self.enable_searchcode = enable_searchcode
        self.enable_gitlab = enable_gitlab
        self.enable_realtime = enable_realtime
        self.enable_sourcegraph = enable_sourcegraph
        self.enable_git_clone = enable_git_clone
        self.git_clone_dir = git_clone_dir
        self.pastebin_api_key = pastebin_api_key

        # 监控模式
        self.monitor_mode = monitor_mode

        # 信号处理
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """信号处理"""
        self.stop()

    async def _init_async_resources(self):
        """初始化异步资源"""
        self.async_db = AsyncDatabase(config.db_path)
        await self.async_db.init()
        logger.info("异步数据库初始化完成")

        pool = await get_connection_pool()
        logger.info(f"连接池初始化完成 (最大连接 {pool.max_connections})")

        if self.enable_cache:
            self.cache_manager = await get_cache_manager(CacheConfig(
                redis_url=self.redis_url,
                validation_ttl=3600.0,
                domain_health_ttl=1800.0,
                key_fingerprint_ttl=86400.0
            ))
            logger.info("缓存管理器已启动")

        if self.enable_performance_monitor:
            self.performance_monitor = get_monitor()
            await self.performance_monitor.start()
            logger.info("性能监控已启动")

        if self.use_dynamic_queue:
            self.result_queue = create_queue(
                initial_size=1000,
                auto_adjust=True,
                memory_threshold=80.0
            )
            await self.result_queue.start()
            logger.info(f"动态队列已启动 (初始大小: 1000)")
        else:
            self.result_queue = asyncio.Queue(maxsize=10000)

    def start(self):
        """启动扫描系统"""
        is_valid, errors = ConfigValidator.validate()
        if not is_valid:
            logger.error("配置验证失败:")
            for error in errors:
                logger.error(f"  - {error}")
            sys.exit(1)

        logger.info("配置验证通过")
        logger.info("=" * 60)
        logger.info("GitHub Secret Scanner Pro")
        logger.info("=" * 60)

        try_enable_uvloop()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._init_async_resources())

        self.dashboard.update_stats(
            total_tokens=len(config.github_tokens),
            is_running=True
        )

        if self.monitor_mode:
            self._start_monitor_mode(loop)
            return

        # 启动验证器（v2.2 优化版）
        from validator_async import start_async_validators
        self.validator_threads = start_async_validators(
            self.result_queue,
            self.async_db,
            self.stop_event,
            dashboard=self.dashboard,
            num_workers=2
        )

        # 启动 GitHub 扫描器（Producer）
        self.scanner_thread = start_scanner(
            self.result_queue,
            self.db,
            self.stop_event,
            dashboard=self.dashboard
        )

        # 可选源扫描器
        if self.enable_pastebin:
            self.pastebin_thread = start_pastebin_scanner(
                self.result_queue, self.db, self.stop_event,
                dashboard=self.dashboard, api_key=self.pastebin_api_key
            )

        if self.enable_gist:
            self.gist_thread = start_gist_scanner(
                self.result_queue, self.db, self.stop_event,
                dashboard=self.dashboard
            )

        if self.enable_searchcode:
            self.searchcode_thread = start_searchcode_scanner(
                self.result_queue, self.db, self.stop_event,
                dashboard=self.dashboard
            )

        if self.enable_gitlab:
            self.gitlab_thread = start_gitlab_scanner(
                self.result_queue, self.db, self.stop_event,
                dashboard=self.dashboard
            )

        if self.enable_realtime:
            self.realtime_thread = start_realtime_scanner(
                self.result_queue, self.db, self.stop_event,
                dashboard=self.dashboard
            )

        if self.enable_sourcegraph:
            self.sourcegraph_thread = start_sourcegraph_scanner(
                self.result_queue, self.db, self.stop_event,
                dashboard=self.dashboard
            )

        if self.enable_git_clone:
            clone_dir = self.git_clone_dir or None
            self.git_clone_thread = start_git_clone_scanner(
                self.result_queue, self.db, self.stop_event,
                dashboard=self.dashboard, clone_dir=clone_dir,
            )

        # 主循环
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
                self.dashboard.render()
        except KeyboardInterrupt:
            self.stop()

    def _start_monitor_mode(self, loop):
        """启动监控模式 —— 持续验证 + 推送"""
        logger.info("启动监控模式（持续验证 + 推送）")
        from notifier import Notifier

        notifier = Notifier(output_file=config.db_path.replace('.db', '_found_keys.txt'))
        db = Database(config.db_path)

        try:
            while not self.stop_event.is_set():
                for key in db.get_unverified_keys():
                    if self.stop_event.is_set():
                        break
                    platform = key.platform or "unknown"
                    notifier.notify_file(platform, key.api_key, key.base_url)
                time.sleep(30)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """停止系统"""
        if self.stop_event.is_set():
            return

        logger.info("正在停止扫描系统...")
        self.dashboard.stop()
        self.stop_event.set()

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        async def cleanup():
            if self.cache_manager:
                logger.info("=" * 60)
                logger.info("缓存统计报告")
                logger.info("=" * 60)
                stats = self.cache_manager.get_stats()
                logger.info(f"验证缓存命中率: {stats['validation']['hit_rate']:.1f}%")
                logger.info(f"域名健康追踪: {stats['domain_health']['size']} 个")
                logger.info(f"死域名数量: {stats['domain_health']['dead']}")

            if self.performance_monitor:
                logger.info("=" * 60)
                logger.info("性能监控报告")
                logger.info("=" * 60)
                self.performance_monitor.print_report()
                await self.performance_monitor.stop()

            if self.use_dynamic_queue and self.result_queue:
                await self.result_queue.stop()
                logger.info("动态队列已关闭")

            if self.enable_cache:
                await close_cache_manager()
                logger.info("缓存管理器已关闭")

            await close_connection_pool()
            logger.info("连接池已关闭")

            if self.async_db:
                await self.async_db.close()
                logger.info("异步数据库已关闭")

        loop.run_until_complete(cleanup())

        threads = [
            self.scanner_thread,
            self.pastebin_thread,
            self.gist_thread,
            self.searchcode_thread,
            self.gitlab_thread,
            self.realtime_thread
            self.git_clone_thread,
        ] + self.validator_threads

        for thread in threads:
            if thread and thread.is_alive():
                thread.join(timeout=5)

        logger.info("扫描系统已停止")


# ============================================================================
#                          导出功能
# ============================================================================

def export_keys(db_path: str, output_file: str, status_filter: str = None):
    """导出 Key（明文）"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    db = Database(db_path)

    if status_filter:
        try:
            status = KeyStatus(status_filter)
            keys = db.get_keys_by_status(status)
        except ValueError:
            console.print(f"[red]无效状态: {status_filter}[/]")
            return
    else:
        keys = db.get_valid_keys()

    if not keys:
        console.print("[yellow]没有符合条件的 Key[/]")
        return

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# GitHub Secret Scanner 导出结果\n")
        f.write(f"# 时间: {datetime.now().isoformat()}\n")
        if status_filter:
            f.write(f"# 状态过滤: {status_filter}\n")
        f.write(f"# 共 {len(keys)} 个 Key\n\n")

        for key in keys:
            f.write(f"{key.api_key}\n")

    console.print(f"[green]成功导出 {len(keys)} 个 Key 到 {output_file}[/]")


def export_keys_csv(db_path: str, output_file: str, status_filter: str = None):
    """导出 CSV"""
    from rich.console import Console

    console = Console()
    db = Database(db_path)

    if status_filter:
        status = KeyStatus(status_filter)
        keys = db.get_keys_by_status(status)
    else:
        keys = db.get_valid_keys()

    if not keys:
        console.print("[yellow]没有符合条件的 Key[/]")
        return

    with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['platform', 'api_key', 'base_url', 'status', 'balance',
                         'source_url', 'model_tier', 'rpm', 'is_high_value'])
        for key in keys:
            writer.writerow([
                key.platform, key.api_key, key.base_url, key.status,
                key.balance, key.source_url, key.model_tier, key.rpm,
                key.is_high_value
            ])

    console.print(f"[green]成功导出 {len(keys)} 个 Key 到 {output_file}[/]")


def show_stats(db_path: str):
    """显示数据库统计"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel

    console = Console()
    db = Database(db_path)
    stats = db.get_stats()
    statuses = stats.get('statuses', {})

    table = Table(show_header=False, box=None)
    table.add_column("指标", style="bold cyan")
    table.add_column("数值")

    table.add_row("[bold]Key 总数[/]", str(stats.get('total', 0)))
    table.add_row("[green]有效[/]", f"[green]{statuses.get('valid', 0)}[/]")
    table.add_row("[yellow]配额耗尽[/]", f"[yellow]{statuses.get('quota_exceeded', 0)}[/]")
    table.add_row("[red]无效[/]", f"[red]{statuses.get('invalid', 0)}[/]")
    table.add_row("[magenta]连接错误[/]", f"[magenta]{statuses.get('connection_error', 0)}[/]")

    if stats.get('platforms'):
        table.add_row("", "")
        table.add_row("[bold]平台分布[/]", "")
        for platform, count in stats['platforms'].items():
            table.add_row(f"  {platform}", str(count))

    console.print(Panel(table, title="数据库统计", border_style="cyan"))


# ============================================================================
#                          主函数
# ============================================================================

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="GitHub Secret Scanner Pro — 统一入口",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
版本特性:
  v2.2  — 智能缓存: 3层缓存架构，减少重复验证 30-50%
         批量验证: 按域名分组，降低网络开销 20-30%
         域名健康度: 避免验证死域名，提升效率
  v2.1  — 连接池管理: 复用 HTTP 连接，减少开销
         智能重试: 指数退避，提高成功率
         动态队列: 根据内存压力自动调整
         性能监控: 实时延迟和吞吐量统计
        """
    )

    parser.add_argument('--export', type=str, metavar='FILE', help='导出 Key 到文本文件')
    parser.add_argument('--export-csv', type=str, metavar='CSV', help='导出 Key 到 CSV 文件')
    parser.add_argument('--status', type=str, help='导出状态过滤 (valid/quota_exceeded)')
    parser.add_argument('--stats', action='store_true', help='显示统计')
    parser.add_argument('--db', type=str, default='leaked_keys.db', help='数据库路径')
    parser.add_argument('--proxy', type=str, help='代理地址')

    # v2.1 选项
    parser.add_argument('--no-monitor', action='store_true', help='禁用性能监控')
    parser.add_argument('--no-dynamic-queue', action='store_true', help='禁用动态队列')

    # v2.2 选项
    parser.add_argument('--no-cache', action='store_true', help='禁用智能缓存')

    # Redis 持久化缓存选项
    parser.add_argument('--redis', type=str, default='', help='Redis 连接地址（可选，设置后启用持久化缓存）')

    # 监控模式
    parser.add_argument('--monitor', action='store_true', help='实时监控+推送模式')

    # 扫描源选项
    parser.add_argument('--pastebin', action='store_true', help='启用 Pastebin 扫描源')
    parser.add_argument('--pastebin-key', type=str, default='', help='Pastebin Pro API Key')
    parser.add_argument('--gist', action='store_true', help='启用 GitHub Gist 扫描源')
    parser.add_argument('--searchcode', action='store_true', help='启用 SearchCode 扫描源')
    parser.add_argument('--gitlab', action='store_true', help='启用 GitLab Snippets 扫描源')
    parser.add_argument('--realtime', action='store_true', help='启用实时监控 (GitHub Events)')
    parser.add_argument('--sourcegraph', action='store_true', help='启用 Sourcegraph 补充扫描源')
    parser.add_argument('--git', action='store_true', help='启用 Git clone 扫描源（绕过 API 限制）')
    parser.add_argument('--git-clone-dir', type=str, default='', help='Git 克隆临时目录（可选）')
    parser.add_argument('--all-sources', action='store_true', help='启用所有扫描源')

    args = parser.parse_args()

    if args.proxy:
        config.proxy_url = args.proxy
    if args.db:
        config.db_path = args.db

    # 导出模式
    if args.export or args.export_csv:
        if args.export:
            export_keys(config.db_path, args.export, args.status)
        if args.export_csv:
            export_keys_csv(config.db_path, args.export_csv, args.status)
        return

    # 统计模式
    if args.stats:
        show_stats(config.db_path)
        return

    # 扫描模式
    enable_pastebin = args.pastebin or args.all_sources
    enable_gist = args.gist or args.all_sources
    enable_searchcode = args.searchcode or args.all_sources
    enable_gitlab = args.gitlab or args.all_sources
    enable_realtime = args.realtime or args.all_sources
    enable_sourcegraph = args.sourcegraph or args.all_sources
    enable_git_clone = args.git

    scanner = SecretScanner(
        enable_pastebin=enable_pastebin,
        enable_gist=enable_gist,
        enable_searchcode=enable_searchcode,
        enable_gitlab=enable_gitlab,
        enable_realtime=enable_realtime,
        enable_sourcegraph=enable_sourcegraph,
        enable_git_clone=enable_git_clone,
        pastebin_api_key=args.pastebin_key,
        enable_performance_monitor=not args.no_monitor,
        enable_cache=not args.no_cache,
        redis_url=args.redis,
        git_clone_dir=args.git_clone_dir,
        monitor_mode=args.monitor
    )

    if args.no_dynamic_queue:
        scanner.use_dynamic_queue = False
        logger.info("动态队列已禁用")

    scanner.start()


if __name__ == "__main__":
    main()
