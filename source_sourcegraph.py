"""
Sourcegraph 低频补充扫描源

特点：
- 无 token 限制，作为 GitHub Code Search 配额耗尽时的补充
- 使用 Sourcegraph 公共搜索流 API（SSE）
- 只用 ENABLED_PROVIDERS 白名单后过滤，不额外匹配无关 provider
- 低频运行：每轮间隔 5 分钟，每关键词最多 1 页结果
"""

import re
import time
import json
import threading
from typing import List, Optional, Set, Dict
from urllib.request import Request, urlopen
from urllib.parse import quote as urlquote
from urllib.error import URLError

from loguru import logger
from config import config, REGEX_PATTERNS
from scanner import ScanResult, calculate_entropy, is_test_key, ENTROPY_THRESHOLD

SOURCEGRAPH_STREAM_URL = "https://sourcegraph.com/.api/search/stream"
REQUEST_TIMEOUT = 30
MAX_RESULTS_PER_QUERY = 15
MAX_RAW_FETCH_PER_QUERY = 15
INTER_KEYWORD_DELAY = 3
INTER_ROUND_DELAY = 300


class SourcegraphScanner:
    """Sourcegraph 补充扫描器"""

    def __init__(
        self,
        result_queue,
        stop_event: threading.Event,
        dashboard=None
    ):
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.dashboard = dashboard

        self._processed_ids: Set[str] = set()
        self._processed_lock = threading.Lock()

        self._key_patterns = {
            platform: re.compile(pattern)
            for platform, pattern in REGEX_PATTERNS.items()
            if platform in config.enabled_detector_platforms
        }

        self.stats = {"searched": 0, "raw_fetched": 0, "raw_failed": 0, "keys_found": 0}

    def _log(self, message: str, level: str = "INFO"):
        logger.info(f"[Sourcegraph] {message}")
        if self.dashboard:
            self.dashboard.add_log(f"[Sourcegraph] {message}", level)

    def _queue_put(self, item):
        """同步放入队列，兼容 DynamicQueue 和 queue.Queue"""
        try:
            if hasattr(self.result_queue, 'put_nowait'):
                ok = self.result_queue.put_nowait(item)
                if ok is False:
                    logger.warning("[Sourcegraph] 队列已满，丢弃结果")
                return ok
            else:
                self.result_queue.put(item, timeout=5)
                return True
        except Exception as exc:
            logger.warning(f"[Sourcegraph] 入队失败: {exc}")
            return False

    def _search(self, keyword: str) -> List[Dict]:
        """查询 Sourcegraph 搜索流，返回 matches 列表"""
        query = f"context:global {keyword} count:{MAX_RESULTS_PER_QUERY}"
        url = f"{SOURCEGRAPH_STREAM_URL}?q={urlquote(query)}"
        req = Request(url, headers={
            "User-Agent": "github-api-scan-sourcegraph/1.0",
            "Accept": "text/event-stream",
        })

        matches = []
        try:
            with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                current_event = None
                for raw_line in resp:
                    if self.stop_event.is_set():
                        break
                    line = raw_line.decode("utf-8", "ignore").strip()
                    if not line:
                        continue
                    if line.startswith("event: "):
                        current_event = line[7:].strip()
                    elif line.startswith("data: ") and current_event == "matches":
                        try:
                            batch = json.loads(line[6:])
                            if isinstance(batch, list):
                                matches.extend(batch)
                        except json.JSONDecodeError:
                            pass
        except (URLError, OSError, TimeoutError) as exc:
            self._log(f"Search failed: {type(exc).__name__}: {exc}", "ERROR")
        except Exception as exc:
            self._log(f"Unexpected error: {type(exc).__name__}: {exc}", "ERROR")

        return matches

    def _build_source_url(self, match: Dict) -> str:
        repo = match.get("repository", "")
        path = match.get("path", "")
        branch = (match.get("branches") or [""])[0]
        if branch:
            return f"https://{repo}/blob/{branch}/{path}"
        return f"https://{repo}/blob/HEAD/{path}"

    def _build_raw_url(self, match: Dict) -> Optional[str]:
        repo = match.get("repository", "")
        path = match.get("path", "")
        branch = (match.get("branches") or [""])[0] or "HEAD"
        if not repo.startswith("github.com/") or not path:
            return None
        repo_path = repo.removeprefix("github.com/").strip("/")
        encoded_path = "/".join(urlquote(part) for part in path.split("/"))
        return f"https://raw.githubusercontent.com/{repo_path}/{urlquote(branch)}/{encoded_path}"

    def _fetch_raw_content(self, raw_url: str) -> Optional[str]:
        try:
            req = Request(raw_url, headers={
                "User-Agent": "github-api-scan-sourcegraph/1.0",
                "Accept": "text/plain,*/*",
            })
            with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                content_length = resp.headers.get("Content-Length")
                if content_length and int(content_length) > 512 * 1024:
                    return None
                return resp.read(512 * 1024 + 1).decode("utf-8", "ignore")[:512 * 1024]
        except Exception:
            return None

    def _extract_content(self, match: Dict) -> str:
        lines = []
        for lm in match.get("lineMatches", []):
            ln = lm.get("lineNumber", "")
            text = lm.get("line", "")
            lines.append(f"{ln}: {text}")
        return "\n".join(lines)

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        results = []
        for platform, pattern in self._key_patterns.items():
            for match in pattern.finditer(content):
                api_key = match.group(0)
                if is_test_key(api_key):
                    continue
                key_body = api_key
                for prefix in ["sk-proj-", "sk-ant-", "sk-", "AIza", "hf_", "gsk_"]:
                    if api_key.startswith(prefix):
                        key_body = api_key[len(prefix):]
                        break
                if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                    continue
                results.append(ScanResult(
                    platform=platform,
                    api_key=api_key,
                    base_url=config.default_base_urls.get(platform, ""),
                    source_url=source_url,
                    context=content[:500]
                ))
        return results

    def _scan_keyword(self, keyword: str) -> int:
        self._log(f"Search: {keyword}", "SCAN")
        found = 0
        matches = self._search(keyword)
        if not matches:
            self._log("  No results", "DEBUG")
            return 0

        self._log(f"  Retrieved {len(matches)} matches", "INFO")
        raw_attempts = 0
        raw_hits = 0
        for match in matches:
            if self.stop_event.is_set():
                break
            mid = f"{match.get('repository', '')}/{match.get('path', '')}/{match.get('commit', '')}"
            with self._processed_lock:
                if mid in self._processed_ids:
                    continue
                self._processed_ids.add(mid)

            self.stats["searched"] += 1
            source_url = self._build_source_url(match)
            if self.dashboard:
                self.dashboard.mark_source_activity("sourcegraph", repos_scanned=1, files_scanned=1, target=source_url)
            content = None
            raw_url = self._build_raw_url(match)
            if raw_url and raw_attempts < MAX_RAW_FETCH_PER_QUERY:
                raw_attempts += 1
                content = self._fetch_raw_content(raw_url)
                if content:
                    raw_hits += 1
                    self.stats["raw_fetched"] += 1
                else:
                    self.stats["raw_failed"] += 1
            if not content:
                content = self._extract_content(match)
            keys = self._extract_keys(content, source_url)
            for kr in keys:
                if self._queue_put(kr):
                    found += 1
                    self.stats["keys_found"] += 1
                    if self.dashboard:
                        self.dashboard.increment_stat("total_keys_found")
                        self.dashboard.increment_source_found("sourcegraph")
                        self.dashboard.mark_source_activity("sourcegraph", keys_found=1)
                    self._log(f"Found {kr.platform.upper()}: {kr.api_key[:15]}...", "FOUND")
        if raw_attempts:
            self._log(f"  GitHub raw fetch {raw_hits}/{raw_attempts} files", "INFO")
        return found

    def run(self):
        self._log("Sourcegraph fallback scanner started", "INFO")
        try:
            while not self.stop_event.is_set():
                try:
                    total_found = 0
                    ordered_keywords = config.get_scheduled_search_keywords()
                    for keyword in ordered_keywords:
                        if self.stop_event.is_set():
                            break
                        found = self._scan_keyword(keyword)
                        total_found += found
                        time.sleep(INTER_KEYWORD_DELAY)

                    if total_found > 0:
                        self._log(f"Round found {total_found} keys", "INFO")
                    else:
                        self._log(f"No new keys this round, waiting {INTER_ROUND_DELAY // 60} minutes", "INFO")

                    for _ in range(INTER_ROUND_DELAY):
                        if self.stop_event.is_set():
                            break
                        time.sleep(1)
                except Exception as exc:
                    self._log(f"Round failed: {type(exc).__name__}: {exc}", "ERROR")
                    time.sleep(30)
        except Exception as exc:
            self._log(f"Scanner fatal error: {type(exc).__name__}: {exc}", "ERROR")
            logger.exception("[Sourcegraph] Scanner thread exited")
        finally:
            self._log("Sourcegraph fallback scanner stopped", "INFO")


def start_sourcegraph_scanner(
    result_queue,
    stop_event: threading.Event,
    dashboard=None
) -> threading.Thread:
    scanner = SourcegraphScanner(result_queue, stop_event, dashboard)
    thread = threading.Thread(target=scanner.run, name="SourcegraphScanner", daemon=True)
    thread.start()
    return thread
