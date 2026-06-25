"""
GitLab Snippets 扫描源 - 从 GitLab 公开 Snippets 搜索 API Key

特点:
- 使用 GitLab API
- 搜索公开 Snippets
- 无需认证（公开数据）
"""

import re
import time
import asyncio
import threading
import queue
from typing import List, Optional, Set
from dataclasses import dataclass

import aiohttp
from aiohttp import ClientTimeout
from loguru import logger

from config import config, REGEX_PATTERNS
from scanner import ScanResult, calculate_entropy, is_test_key, ENTROPY_THRESHOLD


# GitLab API
GITLAB_API = "https://gitlab.com/api/v4"
ASYNC_CONCURRENCY = 20
ASYNC_TIMEOUT = ClientTimeout(total=20, connect=10)

# 搜索关键词
GITLAB_KEYWORDS = [
    "OPENAI_API_KEY",
    "sk-proj-",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "HUGGINGFACE_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
]


@dataclass
class SnippetInfo:
    """Snippet 信息"""
    id: int
    title: str
    web_url: str
    raw_url: str


class GitLabScanner:
    """GitLab Snippets 扫描器"""

    def __init__(
        self,
        result_queue: queue.Queue,
        stop_event: threading.Event,
        dashboard=None
    ):
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.dashboard = dashboard

        self._processed_ids: Set[int] = set()
        self._processed_lock = threading.Lock()

        self._key_patterns = {
            platform: re.compile(pattern)
            for platform, pattern in REGEX_PATTERNS.items()
            if platform != "azure"
        }

        self.stats = {"snippets_scanned": 0, "keys_found": 0}
        self._session: Optional[aiohttp.ClientSession] = None

    def _log(self, message: str, level: str = "INFO"):
        logger.info(f"[GitLab] {message}")
        if self.dashboard:
            self.dashboard.add_log(f"[GitLab] {message}", level)

    def _queue_put(self, item):
        """同步放入队列，兼容 DynamicQueue 和 queue.Queue"""
        try:
            if hasattr(self.result_queue, 'put_nowait'):
                ok = self.result_queue.put_nowait(item)
                if ok is False:
                    logger.warning("[GitLab] 队列已满，丢弃结果")
                return ok
            else:
                self.result_queue.put(item, timeout=5)
                return True
        except Exception as exc:
            logger.warning(f"[GitLab] 入队失败: {exc}")
            return False

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=ASYNC_TIMEOUT, trust_env=True)
        return self._session

    async def _close_session(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _search_snippets(self, keyword: str) -> List[SnippetInfo]:
        """搜索公开 Snippets - 网页抓取方式（API 已要求认证）"""
        snippets = []
        try:
            session = await self._get_session()
            # GitLab public snippets API 要求认证，改用 explore 页面抓取
            url = "https://gitlab.com/explore/snippets"
            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(url, proxy=proxy) as resp:
                if resp.status != 200:
                    self._log(f"explore/snippets 返回 {resp.status}", "ERROR")
                    return []

                html = await resp.text()
                # 解析 snippet 链接: /<user>/<project>/-/snippets/<id>
                import re as _re
                pattern = _re.compile(r'href="(/[^"]+/snippets/(\d+))"')
                seen = set()
                for match in pattern.finditer(html):
                    path = match.group(1)
                    sid = int(match.group(2))
                    if sid in seen:
                        continue
                    seen.add(sid)
                    web_url = f"https://gitlab.com{path}"
                    raw_url = f"https://gitlab.com{path}/raw"
                    snippets.append(SnippetInfo(
                        id=sid,
                        title="",
                        web_url=web_url,
                        raw_url=raw_url
                    ))
        except Exception as e:
            self._log(f"搜索异常: {type(e).__name__}: {e}", "ERROR")

        return snippets

    async def _fetch_content(self, raw_url: str) -> Optional[str]:
        """获取 Snippet 内容"""
        try:
            session = await self._get_session()
            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(raw_url, proxy=proxy) as resp:
                if resp.status == 200:
                    return await resp.text(errors='ignore')
        except Exception:
            pass
        return None

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        """提取 Key"""
        results = []

        for platform, pattern in self._key_patterns.items():
            for match in pattern.finditer(content):
                api_key = match.group(0)

                if is_test_key(api_key):
                    continue

                key_body = api_key
                for prefix in ['sk-proj-', 'sk-ant-', 'sk-', 'AIza', 'hf_', 'gsk_']:
                    if api_key.startswith(prefix):
                        key_body = api_key[len(prefix):]
                        break

                if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                    continue

                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 200)

                results.append(ScanResult(
                    platform=platform,
                    api_key=api_key,
                    base_url=config.default_base_urls.get(platform, ""),
                    source_url=source_url,
                    context=content[start:end]
                ))

        return results

    async def _scan_snippet(self, snippet: SnippetInfo) -> int:
        """扫描单个 Snippet"""
        with self._processed_lock:
            if snippet.id in self._processed_ids:
                return 0
            self._processed_ids.add(snippet.id)

        content = await self._fetch_content(snippet.raw_url)
        if not content:
            return 0

        self.stats["snippets_scanned"] += 1
        results = self._extract_keys(content, snippet.web_url)

        found = 0
        for result in results:
            if self._queue_put(result):
                found += 1
                self.stats["keys_found"] += 1
                if self.dashboard:
                    self.dashboard.increment_stat("total_keys_found")
                    self.dashboard.increment_source_found("gitlab")
                self._log(f"发现 {result.platform.upper()}: {result.api_key[:15]}...", "FOUND")

        return found

    async def _scan_batch(self, snippets: List[SnippetInfo]) -> int:
        """批量扫描"""
        semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY)

        async def scan_one(s):
            async with semaphore:
                return await self._scan_snippet(s)

        tasks = [scan_one(s) for s in snippets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(r for r in results if isinstance(r, int))

    def run(self):
        """运行扫描器"""
        self._log("GitLab 扫描器启动", "INFO")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            while not self.stop_event.is_set():
                total_found = 0

                self._log("获取公开 Snippets...", "SCAN")
                snippets = loop.run_until_complete(self._search_snippets(""))

                if snippets:
                    self._log(f"找到 {len(snippets)} 个 Snippets", "INFO")
                    found = loop.run_until_complete(self._scan_batch(snippets))
                    total_found += found

                if total_found > 0:
                    self._log(f"本轮发现 {total_found} 个 Key", "INFO")

                self._log("等待 5 分钟...", "INFO")
                for _ in range(300):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)

        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        self._log("GitLab 扫描器停止", "INFO")


def start_gitlab_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None
) -> threading.Thread:
    """启动 GitLab 扫描器"""
    scanner = GitLabScanner(result_queue, stop_event, dashboard)
    thread = threading.Thread(target=scanner.run, name="GitLabScanner", daemon=True)
    thread.start()
    return thread
