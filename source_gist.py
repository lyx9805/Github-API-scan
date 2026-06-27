"""
GitHub Gist 扫描源 - 从公开 Gist 中扫描 API Key

使用 GitHub API 搜索公开 Gist
"""

import re
import time
import asyncio
import threading
import queue
from typing import List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timezone

import aiohttp
from aiohttp import ClientTimeout
from github import Github, GithubException
from loguru import logger

from config import config, REGEX_PATTERNS
from scanner import ScanResult, calculate_entropy, is_test_key, ENTROPY_THRESHOLD


# 并发配置
ASYNC_CONCURRENCY = 50
ASYNC_TIMEOUT = ClientTimeout(total=15, connect=8)

# Gist 搜索关键词
GIST_SEARCH_KEYWORDS = [
    "OPENAI_API_KEY",
    "sk-proj-",
    "sk-ant-",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "AIzaSy",
    "hf_",
    "gsk_",
    "HUGGINGFACE_TOKEN",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "ghp_",
    "sk_live_",
]


@dataclass
class GistFile:
    """Gist 文件信息"""
    gist_id: str
    filename: str
    raw_url: str
    html_url: str
    size: int


class GistScanner:
    """
    GitHub Gist 扫描器

    使用 GitHub API 搜索公开 Gist 中的敏感信息
    """

    def __init__(
        self,
        result_queue: queue.Queue,
        stop_event: threading.Event,
        dashboard=None
    ):
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.dashboard = dashboard

        self._github_clients: List[Github] = []
        self._current_client_index = 0
        self._init_github_clients()

        self._processed_gists: Set[str] = set()
        self._processed_lock = threading.Lock()

        self._key_patterns = {
            platform: re.compile(pattern)
            for platform, pattern in REGEX_PATTERNS.items()
            if platform != "azure"
        }

        self.stats = {
            "gists_scanned": 0,
            "keys_found": 0,
        }

        self._session: Optional[aiohttp.ClientSession] = None

    def _log(self, message: str, level: str = "INFO"):
        logger.info(f"[Gist] {message}")
        if self.dashboard:
            self.dashboard.add_log(f"[Gist] {message}", level)

    def _queue_put(self, item):
        """同步放入队列，兼容 DynamicQueue 和 queue.Queue"""
        try:
            if hasattr(self.result_queue, 'put_nowait'):
                ok = self.result_queue.put_nowait(item)
                if ok is False:
                    logger.warning("[Gist] 队列已满，丢弃结果")
                return ok
            else:
                self.result_queue.put(item, timeout=5)
                return True
        except Exception as exc:
            logger.warning(f"[Gist] 入队失败: {exc}")
            return False

    def _init_github_clients(self):
        """初始化 GitHub 客户端"""
        if config.github_tokens:
            for token in config.github_tokens:
                client = Github(
                    login_or_token=token,
                    per_page=30,
                    timeout=config.request_timeout
                )
                self._github_clients.append(client)
        else:
            self._github_clients.append(Github(per_page=30, timeout=config.request_timeout))

    def _get_client(self) -> Github:
        """获取当前 GitHub 客户端"""
        return self._github_clients[self._current_client_index % len(self._github_clients)]

    def _rotate_client(self):
        """轮换客户端"""
        self._current_client_index = (self._current_client_index + 1) % len(self._github_clients)

    async def _get_session(self) -> aiohttp.ClientSession:
        """获取 aiohttp session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=ASYNC_TIMEOUT,
                trust_env=True
            )
        return self._session

    async def _close_session(self):
        """关闭 session"""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _fetch_gist_content(self, raw_url: str) -> Optional[str]:
        """获取 Gist 文件内容"""
        try:
            session = await self._get_session()
            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(raw_url, proxy=proxy) as resp:
                if resp.status == 200:
                    return await resp.text(errors='ignore')
                return None
        except Exception:
            return None

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        """从内容中提取 API Key"""
        results = []

        for platform, pattern in self._key_patterns.items():
            for match in pattern.finditer(content):
                api_key = match.group(0)

                if is_test_key(api_key):
                    continue

                key_body = api_key
                prefixes = ['sk-proj-', 'sk-ant-', 'sk-', 'AIza', 'hf_', 'gsk_']
                for prefix in prefixes:
                    if api_key.startswith(prefix):
                        key_body = api_key[len(prefix):]
                        break

                if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                    continue

                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 200)
                context = content[start:end]

                results.append(ScanResult(
                    platform=platform,
                    api_key=api_key,
                    base_url=config.default_base_urls.get(platform, ""),
                    source_url=source_url,
                    context=context
                ))

        return results

    def _search_gists(self, keyword: str) -> List[GistFile]:
        """搜索包含关键词的公开 Gist"""
        gist_files = []

        try:
            client = self._get_client()
            public_gists = client.get_gists()

            for i, gist in enumerate(public_gists):
                if self.stop_event.is_set():
                    break
                if i >= 100:
                    break

                try:
                    gist_id = gist.id
                    with self._processed_lock:
                        if gist_id in self._processed_gists:
                            continue
                        self._processed_gists.add(gist_id)

                    for filename, file_info in gist.files.items():
                        raw_url = file_info.raw_url
                        if raw_url:
                            gist_files.append(GistFile(
                                gist_id=gist_id,
                                filename=filename,
                                raw_url=raw_url,
                                html_url=gist.html_url,
                                size=file_info.size or 0
                            ))
                except Exception:
                    continue

        except GithubException as e:
            if "rate limit" in str(e).lower():
                self._log("GitHub API rate limited, waiting...", "WARN")
                self._rotate_client()
                time.sleep(60)
            else:
                self._log(f"GitHub API error: {str(e)[:50]}", "ERROR")
        except Exception as e:
            self._log(f"Search failed: {type(e).__name__}", "ERROR")

        return gist_files

    async def _scan_gist_file(self, gist_file: GistFile) -> int:
        """扫描单个 Gist 文件"""
        content = await self._fetch_gist_content(gist_file.raw_url)
        if not content:
            return 0

        self.stats["gists_scanned"] += 1
        if self.dashboard:
            self.dashboard.mark_source_activity(
                "gist",
                source_type="public_gist",
                target=gist_file.html_url,
                candidates_discovered=1,
                files_scanned=1,
            )

        results = self._extract_keys(content, gist_file.html_url)

        for result in results:
            if self._queue_put(result):
                self.stats["keys_found"] += 1
                if self.dashboard:
                    self.dashboard.increment_stat("total_keys_found")
                    self.dashboard.increment_source_found("gist")
                    self.dashboard.mark_source_activity("gist", keys_found=1)
                self._log(f"Found {result.platform.upper()} key: {result.api_key[:12]}...", "FOUND")

        return len(results)

    async def _scan_batch(self, gist_files: List[GistFile]) -> int:
        """批量扫描 Gist 文件"""
        semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY)

        async def scan_one(gf):
            async with semaphore:
                return await self._scan_gist_file(gf)

        tasks = [scan_one(gf) for gf in gist_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(r for r in results if isinstance(r, int))

    def run(self):
        """运行扫描器主循环"""
        self._log("Gist scanner started", "INFO")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            while not self.stop_event.is_set():
                total_found = 0

                self._log("Fetching public gists...", "SCAN")
                gist_files = self._search_gists("")

                if gist_files:
                    self._log(f"Found {len(gist_files)} gist files", "INFO")
                    found = loop.run_until_complete(self._scan_batch(gist_files))
                    total_found += found

                self._rotate_client()

                if total_found > 0:
                    self._log(f"Round found {total_found} keys", "INFO")

                self._log("Waiting 3 minutes before next round...", "INFO")
                for _ in range(180):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)

        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        self._log("Gist scanner stopped", "INFO")


def start_gist_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None
) -> threading.Thread:
    """启动 Gist 扫描器线程"""
    scanner = GistScanner(result_queue, stop_event, dashboard)
    thread = threading.Thread(
        target=scanner.run,
        name="GistScanner",
        daemon=True
    )
    thread.start()
    return thread
