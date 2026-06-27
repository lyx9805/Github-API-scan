"""
扫描器模块 - GitHub 代码搜索生产者

核心功能：
1. 智能提取 (Key, Base_URL) 绑定对
2. 熵值检测 - 过滤低质量 Key (如 sk-test-123)
3. 域名黑名单 - 过滤 localhost 等垃圾 URL
4. 上下文感知 - 智能提取中转站 URL
5. Azure 特殊识别
"""

import re
import os
import math
import time
import queue
import asyncio
import threading
import urllib.request
import json
from datetime import datetime, timezone
from typing import Optional, List, Set, Tuple
from dataclasses import dataclass
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from github import Github, GithubException, RateLimitExceededException
from loguru import logger

from config import (
    config, REGEX_PATTERNS, BASE_URL_PATTERNS,
    AZURE_URL_PATTERN, AZURE_CONTEXT_KEYWORDS, URL_PRIORITY_KEYWORDS, score_search_keyword
)
from proxy_pool import init_proxy_pool, get_proxy_pool
from database import Database, LeakedKey, KeyStatus




# ============================================================================
#                              常量定义
# ============================================================================

# 熵值阈值（低于此值的 Key 视为测试/假数据）
# 经验值: 3.8 更严格过滤，减少假阳性（测试后可调整至 4.0）
ENTROPY_THRESHOLD = 3.8

# 异步下载配置
# 并发数从 80 降至 60，降低重试开销，提升稳定性
ASYNC_DOWNLOAD_CONCURRENCY = 60
ASYNC_DOWNLOAD_TIMEOUT = ClientTimeout(total=15, connect=8)

# 文件过滤配置
MAX_FILE_SIZE_KB = 500  # 最大文件大小 (KB)

# 允许扫描的文件后缀
ALLOWED_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx',  # 代码文件
    '.env', '.env.local', '.env.production', '.env.development',  # 环境文件
    '.yml', '.yaml', '.toml',  # 配置文件
    '.sh', '.bash', '.zsh',  # Shell 脚本
    '.php', '.rb', '.go', '.rs', '.java',  # 其他语言
    '.conf', '.cfg', '.ini',  # 配置文件
    '.dockerfile', '',  # Dockerfile 无后缀
}

# 必须跳过的文件后缀（即使包含 Key 也不扫描）
BLOCKED_EXTENSIONS = {
    '.lock', '.min.js', '.min.css', '.map',  # 生成文件
    '.md', '.rst', '.txt',  # 文档文件
    '.html', '.htm', '.css', '.scss', '.less',  # 前端文件
    '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico',  # 图片
    '.woff', '.woff2', '.ttf', '.eot',  # 字体
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',  # 文档
    '.zip', '.tar', '.gz', '.rar',  # 压缩文件
    '.exe', '.dll', '.so', '.dylib',  # 二进制
    '.pyc', '.pyo', '.class',  # 编译文件
    '.ipynb', '.csv',  # Jupyter Notebook 和数据文件（常含示例 Key）
}

# 文件路径黑名单（路径中包含这些字符串则跳过）
PATH_BLACKLIST = [
    '/test/', '/tests/', '/__tests__/',
    '/spec/', '/specs/',
    '/mock/', '/mocks/', '/__mocks__/',
    '/fixture/', '/fixtures/',
    '/example/', '/examples/',
    '/sample/', '/samples/',
    '/demo/', '/demos/',
    '/doc/', '/docs/',
    '/vendor/', '/node_modules/', '/venv/', '/.venv/',
    '/dist/', '/build/', '/out/',
    '/coverage/', '/.github/ISSUE_TEMPLATE/',
    # 新增：沙箱/测试环境目录
    '/sandbox/', '/playground/', '/staging/',
    '/tutorial/', '/tutorials/',
    '/workshop/', '/workshops/',
    '/boilerplate/', '/starter/',
]

# 域名黑名单（包含这些子串的 URL 直接跳过）
DOMAIN_BLACKLIST = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'example.com',
    'test.com',
    'my-api',
    'your-api',
    'xxx',
    'placeholder',
    'fake',
    'dummy',
    'sample',
    'mock',
    # 开发/测试环境域名
    'staging.',
    'sandbox.',
    'dev.',
    'demo.',
    'test.',
    '.local',
    '.internal',
    'ngrok.io',
    'localtunnel',
]

# 无效 base_url 黑名单（这些网站不是 API 中转站）
INVALID_BASE_URL_DOMAINS = [
    # 文档网站
    'docs.djangoproject.com',
    'docs.python.org',
    'developer.mozilla.org',
    'stackoverflow.com',
    'medium.com',
    'dev.to',
    'readthedocs.io',
    'gitbook.io',
    # 其他 API 服务（非 OpenAI 兼容）
    'themoviedb.org',
    'tmdb.org',
    'spotify.com',
    'twitter.com',
    'facebook.com',
    'google.com/maps',
    'maps.googleapis.com',
    'youtube.com',
    # 工具/框架网站
    'prisma.io',
    'pris.ly',
    'vercel.com',
    'netlify.com',
    'heroku.com',
    'railway.app',
    'render.com',
    # 其他无关网站
    'every.to',
    'makersuite.google.com',
    'prompthor.com',
    'agentrouter.org',  # 保留，看起来是真实中转站
]

# 已知有效中转站域名特征（优先级更高）
KNOWN_RELAY_DOMAINS = [
    'api.openai.com',
    'api.anthropic.com',
    # 常见中转站
    'api.siliconflow.cn',
    'api.deepseek.com',
    'api.moonshot.cn',
    'api.zhipuai.cn',
    'api.baichuan-ai.com',
    'api.minimax.chat',
    'api.lingyiwanwu.com',
    # 中转站特征关键词
    'openai',
    'chatgpt',
    'gpt',
    'llm',
    'ai-gateway',
    'one-api',
    'new-api',
    'chat-api',
]

# 测试 Key 关键词（Key 中包含这些则跳过）
TEST_KEY_PATTERNS = [
    # 基础测试关键词
    'test', 'demo', 'example', 'sample', 'fake', 'dummy', 'placeholder',
    'xxx', 'your_', 'your-', '<your', '{your', 'abcdef', '123456',
    'insert', 'replace', 'xxxxxx', 'aaaaaa',
    # 开发/测试环境关键词
    'dev_', 'dev-', 'staging', 'sandbox', 'tutorial', 'workshop',
    'playground', 'temp_', 'tmp_', 'mock_', 'stub_',
    # 新增：更多假值模式
    'changeme', 'fixme', 'todo', 'secret', 'password', 'credential',
    'redacted', 'hidden', 'masked', 'obfuscated', 'censored',
    'null', 'none', 'undefined', 'empty', 'blank',
    'default', 'template', 'boilerplate', 'skeleton',
    # 常见占位符
    'api_key_here', 'your_api_key', 'enter_key', 'put_key',
    'add_your', 'fill_in', 'replace_with', 'insert_your',
]

# 高熵值假阳性模式（看起来像真 Key 但实际是假的）
HIGH_ENTROPY_FALSE_POSITIVES = [
    # Base64 编码的常见字符串
    'dGVzdA==',  # "test"
    'ZXhhbXBsZQ==',  # "example"
    'c2FtcGxl',  # "sample"
    # UUID 格式（不是 API Key）
    r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',
]


# ============================================================================
#                              文件过滤工具
# ============================================================================

def should_skip_file(file_path: str, file_size: int = 0) -> Tuple[bool, str]:
    """
    检查文件是否应该跳过
    
    Args:
        file_path: 文件路径
        file_size: 文件大小 (字节)
        
    Returns:
        (should_skip, reason)
    """
    file_path_lower = file_path.lower()
    
    # 1. 检查文件大小
    if file_size > 0 and file_size > MAX_FILE_SIZE_KB * 1024:
        return True, f"file_too_large:{file_size//1024}KB"
    
    # 2. 检查路径黑名单
    for blacklist_path in PATH_BLACKLIST:
        if blacklist_path in file_path_lower:
            return True, f"path_blacklist:{blacklist_path}"
    
    # 3. 检查文件后缀 - 先检查必须屏蔽的
    # 获取文件后缀
    ext = ''
    if '.' in file_path:
        # 处理 .min.js 等复合后缀
        if file_path_lower.endswith('.min.js'):
            ext = '.min.js'
        elif file_path_lower.endswith('.min.css'):
            ext = '.min.css'
        else:
            ext = '.' + file_path.rsplit('.', 1)[-1].lower()
    
    # 检查是否在屏蔽列表
    if ext in BLOCKED_EXTENSIONS:
        return True, f"blocked_ext:{ext}"
    
    # 4. 如果有后缀，检查是否在允许列表
    #    注意：共享的文件类型可能没有后缀（如 Dockerfile）或后缀不在列表中
    #    这种情况不跳过，继续扫描
    
    # 特殊文件名检查 - 这些文件一定要扫描
    important_files = ['dockerfile', '.env', 'config', 'secret', 'credential']
    file_name = file_path.rsplit('/', 1)[-1].lower() if '/' in file_path else file_path.lower()
    if any(imp in file_name for imp in important_files):
        return False, ""
    
    return False, ""


# ============================================================================
#                              数据模型
# ============================================================================

@dataclass
class ScanResult:
    """扫描结果数据类"""
    platform: str       # openai, azure, gemini, anthropic, relay
    api_key: str        # API Key
    base_url: str       # 绑定的 Base URL
    source_url: str     # GitHub 文件 URL
    is_azure: bool = False
    is_relay: bool = False  # 是否为中转站
    context: str = ""


# ============================================================================
#                              工具函数
# ============================================================================

@lru_cache(maxsize=4096)
def calculate_entropy(s: str) -> float:
    """
    计算字符串的香农熵 (Shannon Entropy) - 带 LRU 缓存

    真正的 API Key 熵值高（看起来像乱码）
    测试 Key (如 sk-test-12345) 熵值低（有规律）

    Args:
        s: 输入字符串

    Returns:
        熵值（0-8 之间，越高越随机）
    """
    if not s:
        return 0.0

    # 统计字符频率
    freq = Counter(s)
    length = len(s)

    # 计算熵
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


@lru_cache(maxsize=2048)
def is_test_key(api_key: str) -> bool:
    """
    检测是否为测试/示例 Key - 带 LRU 缓存

    Args:
        api_key: API Key

    Returns:
        是否为测试 Key
    """
    key_lower = api_key.lower()
    return any(pattern in key_lower for pattern in TEST_KEY_PATTERNS)


@lru_cache(maxsize=1024)
def is_blacklisted_url(url: str) -> bool:
    """
    检测 URL 是否在黑名单中 - 带 LRU 缓存

    Args:
        url: URL 字符串

    Returns:
        是否在黑名单中
    """
    if not url:
        return False

    url_lower = url.lower()
    return any(blacklist in url_lower for blacklist in DOMAIN_BLACKLIST)


def mask_key(api_key: str) -> str:
    """遮蔽 API Key"""
    if len(api_key) <= 12:
        return api_key[:4] + "..." + api_key[-4:]
    return api_key[:8] + "..." + api_key[-4:]


# ============================================================================
#                              扫描器类
# ============================================================================

class GitHubScanner:
    """
    GitHub 代码扫描器（生产者）
    
    核心改进：
    1. 熵值过滤 - 跳过低熵值的测试 Key
    2. 域名黑名单 - 跳过 localhost 等
    3. 智能 URL 提取
    """
    
    def __init__(
        self, 
        result_queue: queue.Queue,
        db: Database,
        stop_event: threading.Event,
        dashboard = None  # UI 仪表盘
    ):
        self.result_queue = result_queue
        self.db = db
        self.stop_event = stop_event
        self.dashboard = dashboard
        
        # GitHub 客户端池
        self._github_clients: List[Github] = []
        self._current_client_index = 0
        self._client_lock = threading.Lock()
        self._max_results_per_keyword = int(os.getenv("MAX_SEARCH_RESULTS_PER_KEYWORD", "100"))
        self._token_quota = {}
        self._request_backoff_until = 0.0
        self._request_backoff_seconds = 0.0
        
        self._init_github_clients()

        # 已处理的 Key 集合（内存缓存，加速查询）
        self._processed_keys: Set[str] = set()
        self._processed_lock = threading.Lock()
        
        # 已处理的文件 SHA 集合（内存缓存，加速查询）
        # 注意：持久化存储在数据库 scanned_blobs 表中
        self._processed_shas: Set[str] = set()
        self._sha_lock = threading.Lock()
        
        # 从数据库预加载已扫描的 SHA（可选，用于加速）
        self._preload_scanned_shas()
        
        # 编译正则
        self._key_patterns = {
            platform: re.compile(pattern)
            for platform, pattern in REGEX_PATTERNS.items()
        }
        self._base_url_patterns = [
            re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for pattern in BASE_URL_PATTERNS
        ]
        self._azure_url_pattern = re.compile(AZURE_URL_PATTERN, re.IGNORECASE)
        
        # 统计
        self.stats = {
            "total_found": 0,
            "files_scanned": 0,
            "skipped_entropy": 0,
            "skipped_blacklist": 0,
            "skipped_sha": 0,
            "skipped_file_filter": 0,
        }
        
        # 异步下载组件
        self._async_semaphore = asyncio.Semaphore(ASYNC_DOWNLOAD_CONCURRENCY)
        self._aiohttp_session: Optional[aiohttp.ClientSession] = None
        # 事件循环复用 - 避免频繁创建/销毁
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_lock = threading.Lock()
    
    def _init_github_clients(self):
        """初始化 GitHub 客户端池"""
        dynamic_source_url = getattr(config, "dynamic_proxy_source_url", "")
        if getattr(config, "proxy_urls", None) or dynamic_source_url:
            init_proxy_pool(config.proxy_urls, dynamic_source_url)
            os.environ.pop('HTTP_PROXY', None)
            os.environ.pop('HTTPS_PROXY', None)
        elif config.proxy_url:
            os.environ['HTTP_PROXY'] = config.proxy_url
            os.environ['HTTPS_PROXY'] = config.proxy_url
        else:
            os.environ.pop('HTTP_PROXY', None)
            os.environ.pop('HTTPS_PROXY', None)
        
        if config.github_tokens:
            for token in config.github_tokens:
                client = Github(
                    login_or_token=token,
                    per_page=100,
                    timeout=config.request_timeout,
                )
                self._github_clients.append(client)
        else:
            client = Github(per_page=100, timeout=config.request_timeout)
            self._github_clients.append(client)
    
    def _get_github_client(self) -> Github:
        with self._client_lock:
            return self._github_clients[self._current_client_index % len(self._github_clients)]
    
    def _rotate_client(self) -> int:
        with self._client_lock:
            self._current_client_index = (self._current_client_index + 1) % len(self._github_clients)
            return self._current_client_index

    def _token_quota_entry(self, index: int) -> dict:
        return self._token_quota.setdefault(index, {
            "remaining": None,
            "limit": None,
            "reset": None,
            "disabled_until": 0.0,
            "last_checked": 0.0,
            "last_error": "",
            "success_count": 0,
            "failure_count": 0,
            "rate_limit_count": 0,
            "health_score": 100.0,
            "last_success_at": 0.0,
        })

    def _refresh_token_quota(self, index: int, force: bool = False) -> dict:
        """刷新单个 token 的 Code Search 配额缓存。"""
        entry = self._token_quota_entry(index)
        now_ts = time.time()
        if not force and now_ts - entry.get("last_checked", 0) < 15:
            return entry
        try:
            headers = {
                "Accept": "application/vnd.github+json",
                "User-Agent": "github-api-scan/2.2",
            }
            if config.github_tokens and index < len(config.github_tokens):
                headers["Authorization"] = f"Bearer {config.github_tokens[index]}"
            req = urllib.request.Request("https://api.github.com/rate_limit", headers=headers)
            with urllib.request.urlopen(req, timeout=config.request_timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            resources = data.get("resources", {})
            search = resources.get("code_search") or resources.get("search") or {}
            remaining = int(search.get("remaining") or 0)
            limit = int(search.get("limit") or 0)
            reset_ts = float(search.get("reset") or 0.0)
            entry.update({
                "remaining": remaining,
                "limit": limit,
                "reset": reset_ts,
                "disabled_until": reset_ts + 5 if remaining <= 0 and reset_ts else 0.0,
                "last_checked": now_ts,
                "last_error": "",
            })
        except Exception as exc:
            entry.update({
                "remaining": 0,
                "disabled_until": now_ts + 30,
                "last_checked": now_ts,
                "last_error": type(exc).__name__,
            })
        return entry

    def _record_token_success(self, index: int):
        entry = self._token_quota_entry(index)
        entry["success_count"] = int(entry.get("success_count", 0)) + 1
        entry["failure_count"] = max(0, int(entry.get("failure_count", 0)) - 1)
        entry["last_success_at"] = time.time()
        entry["health_score"] = min(100.0, float(entry.get("health_score", 100.0)) + 5.0)

    def _record_token_failure(self, index: int, reason: str = "error", cooldown: float = 0.0):
        entry = self._token_quota_entry(index)
        entry["failure_count"] = int(entry.get("failure_count", 0)) + 1
        entry["last_error"] = reason
        entry["health_score"] = max(5.0, float(entry.get("health_score", 100.0)) - 15.0)
        if cooldown > 0:
            entry["disabled_until"] = max(float(entry.get("disabled_until", 0.0)), time.time() + cooldown)

    def _record_token_rate_limit(self, index: int, cooldown: float = 60.0):
        entry = self._token_quota_entry(index)
        entry["rate_limit_count"] = int(entry.get("rate_limit_count", 0)) + 1
        entry["remaining"] = 0
        entry["last_error"] = "rate_limit"
        entry["health_score"] = max(0.0, float(entry.get("health_score", 100.0)) - 25.0)
        entry["disabled_until"] = max(float(entry.get("disabled_until", 0.0)), time.time() + cooldown)

    def _apply_request_backoff(self, base_seconds: float, reason: str):
        self._request_backoff_seconds = min(120.0, max(base_seconds, self._request_backoff_seconds * 1.8 if self._request_backoff_seconds else base_seconds))
        self._request_backoff_until = time.time() + self._request_backoff_seconds
        self._log(f"Request backoff {self._request_backoff_seconds:.0f}s ({reason})", "WARN")

    def _wait_for_request_backoff(self):
        while self._request_backoff_until > time.time() and not self.stop_event.is_set():
            remaining = self._request_backoff_until - time.time()
            time.sleep(min(5, remaining))

    def _relax_request_backoff(self):
        if self._request_backoff_seconds <= 0:
            return
        self._request_backoff_seconds = max(0.0, self._request_backoff_seconds * 0.5 - 1.0)
        if self._request_backoff_seconds <= 0:
            self._request_backoff_until = 0.0
        else:
            self._request_backoff_until = max(self._request_backoff_until, time.time() + min(self._request_backoff_seconds, 5.0))

    def _mark_current_token_exhausted(self):
        """把当前 token 临时标记为 code_search 不可用。"""
        index = self._current_client_index % len(self._github_clients)
        entry = self._refresh_token_quota(index, force=True)
        if not entry.get("disabled_until"):
            entry["disabled_until"] = time.time() + 60
        entry["remaining"] = 0

    def _select_available_client(self) -> bool:
        """选择还有 Code Search 配额且健康度更高的客户端。"""
        if not self._github_clients:
            return False
        now_ts = time.time()
        best_wait_until = None
        best_index = None
        best_score = None
        start = self._current_client_index % len(self._github_clients)
        for offset in range(len(self._github_clients)):
            index = (start + offset) % len(self._github_clients)
            entry = self._token_quota_entry(index)
            if entry.get("disabled_until", 0) > now_ts:
                best_wait_until = min(best_wait_until or entry["disabled_until"], entry["disabled_until"])
                continue
            entry = self._refresh_token_quota(index)
            if (entry.get("remaining") or 0) <= 0:
                if entry.get("disabled_until", 0) > now_ts:
                    best_wait_until = min(best_wait_until or entry["disabled_until"], entry["disabled_until"])
                continue
            health_score = float(entry.get("health_score", 100.0))
            remaining = float(entry.get("remaining") or 0)
            composite = health_score * 1000.0 + remaining
            if best_score is None or composite > best_score:
                best_score = composite
                best_index = index
        if best_index is not None:
            with self._client_lock:
                self._current_client_index = best_index
            if self.dashboard:
                self.dashboard.update_stats(current_token_index=best_index, total_tokens=len(self._github_clients))
            return True
        if best_wait_until:
            wait = max(0, best_wait_until - now_ts)
            self._log(f"All tokens are temporarily unavailable for Code Search, retry in about {wait:.0f}s", "WARN")
        return False

    def _preload_scanned_shas(self):
        """
        从数据库预加载已扫描的 SHA 到内存缓存
        
        这样可以避免每次都查询数据库，提升性能
        """
        try:
            count = self.db.get_scanned_blob_count()
            if count > 0:
                self._log(f"已从数据库加载 {count} 个已扫描文件 SHA", "INFO")
        except Exception as e:
            self._log(f"预加载 SHA 失败: {e}", "WARN")
    
    def _get_event_loop(self) -> asyncio.AbstractEventLoop:
        """获取或创建事件循环 - 线程安全复用"""
        with self._loop_lock:
            if self._event_loop is None or self._event_loop.is_closed():
                self._event_loop = asyncio.new_event_loop()
            return self._event_loop

    async def _get_aiohttp_session(self) -> aiohttp.ClientSession:
        """获取或创建 aiohttp session - 全局复用"""
        if self._aiohttp_session is None or self._aiohttp_session.closed:
            connector = TCPConnector(
                limit=ASYNC_DOWNLOAD_CONCURRENCY,
                limit_per_host=20,  # 单主机连接限制
                ttl_dns_cache=300,  # DNS 缓存 5 分钟
                keepalive_timeout=30,  # 保持连接 30 秒
                enable_cleanup_closed=True
            )
            self._aiohttp_session = aiohttp.ClientSession(
                connector=connector,
                timeout=ASYNC_DOWNLOAD_TIMEOUT,
                trust_env=True
            )
        return self._aiohttp_session
    
    async def _close_aiohttp_session(self):
        """关闭 aiohttp session"""
        if self._aiohttp_session and not self._aiohttp_session.closed:
            await self._aiohttp_session.close()
    
    async def _async_download_file(self, raw_url: str) -> Optional[str]:
        """
        异步下载文件内容
        
        使用 aiohttp 替代 requests，大幅提升速度
        """
        async with self._async_semaphore:
            proxy_pool = get_proxy_pool()
            proxy = None
            if proxy_pool and proxy_pool.has_healthy_proxy:
                proxy = await proxy_pool.get_proxy()
            elif config.proxy_url:
                proxy = config.proxy_url

            try:
                session = await self._get_aiohttp_session()
                async with session.get(raw_url, proxy=proxy) as resp:
                    if resp.status == 200:
                        if proxy_pool and proxy:
                            await proxy_pool.report_success(proxy)
                        return await resp.text(errors='ignore')
                    if proxy_pool and proxy:
                        await proxy_pool.report_failure(proxy)
                    return None
            except asyncio.TimeoutError:
                if proxy_pool and proxy:
                    await proxy_pool.report_failure(proxy)
                return None
            except aiohttp.ClientError:
                if proxy_pool and proxy:
                    await proxy_pool.report_failure(proxy)
                return None
            except Exception:
                if proxy_pool and proxy:
                    await proxy_pool.report_failure(proxy)
                return None
    
    async def _async_download_batch(
        self, 
        files_metadata: List[Tuple[str, str, any]]
    ) -> List[Tuple[str, str, str]]:
        """
        批量异步下载文件
        
        Args:
            files_metadata: [(raw_url, html_url, code_file), ...]
            
        Returns:
            [(html_url, content, code_file), ...] 成功下载的文件
        """
        async def download_one(raw_url: str, html_url: str, code_file):
            content = await self._async_download_file(raw_url)
            if content:
                return (html_url, content, code_file)
            return None
        
        tasks = [
            download_one(raw_url, html_url, code_file)
            for raw_url, html_url, code_file in files_metadata
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 过滤掉失败的和异常
        return [
            r for r in results 
            if r is not None and not isinstance(r, Exception)
        ]
    
    def _run_async_download(self, files_metadata: List[Tuple[str, str, any]]) -> List[Tuple[str, str, str]]:
        """
        在同步上下文中运行异步下载 - 复用事件循环

        使用持久化事件循环避免频繁创建/销毁开销
        """
        loop = self._get_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._async_download_batch(files_metadata))
        except Exception as e:
            logger.debug(f"异步下载异常: {type(e).__name__}: {e}")
            return []
    
    def _is_key_processed(self, api_key: str) -> bool:
        with self._processed_lock:
            if api_key in self._processed_keys:
                return True
            key_exists = getattr(self.db, "key_exists_sync", self.db.key_exists)
            if key_exists(api_key):
                self._processed_keys.add(api_key)
                return True
            return False
    
    def _mark_key_processed(self, api_key: str):
        with self._processed_lock:
            self._processed_keys.add(api_key)
    
    def _is_sha_processed(self, sha: str) -> bool:
        """
        检查文件 SHA 是否已处理过（双层检查）
        
        1. 先查内存缓存（快）
        2. 再查数据库（持久化）
        """
        if not sha:
            return False
        
        # 1. 内存缓存检查
        with self._sha_lock:
            if sha in self._processed_shas:
                return True
        
        # 2. 数据库检查（持久化）
        is_blob_scanned = getattr(self.db, "is_blob_scanned_sync", self.db.is_blob_scanned)
        if is_blob_scanned(sha):
            # 同步到内存缓存
            with self._sha_lock:
                self._processed_shas.add(sha)
            return True
        
        return False
    
    def _mark_sha_processed(self, sha: str):
        """
        标记文件 SHA 为已处理（双层写入）
        
        1. 写入内存缓存
        2. 持久化到数据库
        """
        if not sha:
            return
        
        # 1. 内存缓存
        with self._sha_lock:
            self._processed_shas.add(sha)
        
        # 2. 持久化到数据库
        mark_blob_scanned = getattr(self.db, "mark_blob_scanned_sync", self.db.mark_blob_scanned)
        mark_blob_scanned(sha)
    
    def _log(self, message: str, level: str = "INFO"):
        """输出日志到仪表盘和 loguru（确保 Docker 容器日志可见）"""
        if self.dashboard:
            self.dashboard.add_log(message, level)
        # 同时写到 loguru，Docker 容器日志可见
        from loguru import logger as _logger
        lvl = level.lower() if level else "info"
        log_fn = getattr(_logger, lvl, _logger.info)
        log_fn(f"[GitHubScanner] {message}")
    
    # ========================================================================
    #                           过滤逻辑
    # ========================================================================
    
    def _should_skip_key(self, api_key: str) -> tuple:
        """
        检查是否应该跳过这个 Key (增强版)
        
        过滤规则：
        1. 测试 Key 检测
        2. 熵值过滤
        3. 重复字符检测
        4. 常见假值模式
        
        Returns:
            (should_skip, reason)
        """
        # 1. 检查是否为测试 Key
        if is_test_key(api_key):
            return True, "test_key"
        
        # 2. 去掉前缀后计算
        key_body = api_key
        prefixes = ['sk-proj-', 'sk-ant-', 'sk-', 'AIza', 'hf_', 'gsk_']
        for prefix in prefixes:
            if api_key.startswith(prefix):
                key_body = api_key[len(prefix):]
                break
        
        # 3. 熵值过滤
        entropy = calculate_entropy(key_body)
        if entropy < ENTROPY_THRESHOLD:
            return True, f"low_entropy:{entropy:.2f}"
        
        # 4. 重复字符检测 (如 aaaaaaa, 1111111)
        if len(set(key_body)) < 5:
            return True, "repetitive_chars"
        
        # 5. 常见假值模式
        fake_patterns = [
            'your_api_key', 'your-api-key', 'api_key_here',
            'insert_key', 'replace_me', 'placeholder',
            'xxxxxxxx', 'yyyyyyyy', '12345678', 'abcdefgh',
            'test1234', 'demo1234', 'sample12'
        ]
        key_lower = api_key.lower()
        for pattern in fake_patterns:
            if pattern in key_lower:
                return True, f"fake_pattern:{pattern}"
        
        # 6. 连续字符检测 (如 abcdefgh, 12345678)
        if self._has_sequential_chars(key_body, 6):
            return True, "sequential_chars"
        
        return False, ""
    
    def _has_sequential_chars(self, s: str, min_len: int = 6) -> bool:
        """检测连续递增/递减字符"""
        if len(s) < min_len:
            return False
        count = 1
        for i in range(1, len(s)):
            if ord(s[i]) == ord(s[i-1]) + 1 or ord(s[i]) == ord(s[i-1]) - 1:
                count += 1
                if count >= min_len:
                    return True
            else:
                count = 1
        return False
    
    def _should_skip_url(self, url: str) -> tuple:
        """
        检查是否应该跳过这个 URL
        
        Returns:
            (should_skip, reason)
        """
        if is_blacklisted_url(url):
            return True, "blacklisted"
        return False, ""
    
    # ========================================================================
    #                           上下文提取
    # ========================================================================
    
    def _extract_context(self, content: str, key_pos: int) -> str:
        """提取 Key 周围的上下文"""
        lines = content.split('\n')
        line_num = content[:key_pos].count('\n')
        
        start_line = max(0, line_num - config.context_window)
        end_line = min(len(lines), line_num + config.context_window + 1)
        
        return '\n'.join(lines[start_line:end_line])
    
    def _is_azure_context(self, context: str) -> bool:
        """检查是否为 Azure 上下文"""
        context_lower = context.lower()
        return any(kw.lower() in context_lower for kw in AZURE_CONTEXT_KEYWORDS)
    
    def _extract_azure_endpoint(self, context: str) -> Optional[str]:
        """提取 Azure Endpoint"""
        match = self._azure_url_pattern.search(context)
        return match.group(0) if match else None
    
    def _is_valid_relay_url(self, url: str) -> bool:
        """
        检查 URL 是否可能是有效的 API 中转站
        
        排除文档网站、无关 API 等
        """
        url_lower = url.lower()
        
        # 1. 检查无效域名黑名单
        for invalid_domain in INVALID_BASE_URL_DOMAINS:
            if invalid_domain in url_lower:
                return False
        
        # 2. 检查是否包含已知中转站特征
        for relay_keyword in KNOWN_RELAY_DOMAINS:
            if relay_keyword in url_lower:
                return True
        
        # 3. 检查 URL 路径是否像 API 端点
        # 真正的中转站通常是简短的域名，不会有复杂路径
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            path = parsed.path.strip('/')
            
            # 排除有复杂路径的 URL（通常是文档链接）
            if path and '/' in path and len(path) > 20:
                return False
            
            # 排除明显的文档/设置页面
            doc_indicators = ['docs', 'settings', 'ref/', 'guide', 'tutorial', 'help']
            if any(ind in path.lower() for ind in doc_indicators):
                return False
                
        except Exception as e:
            logger.debug(f"异常: {type(e).__name__}")
        
        return True
    
    def _extract_base_url(self, context: str, platform: str) -> tuple:
        """
        从上下文提取 Base URL
        
        优化：增加中转站有效性检测
        
        Returns:
            (url, is_relay)
        """
        found_urls = []
        
        for pattern in self._base_url_patterns:
            for match in pattern.finditer(context):
                url = match.group(1) if match.lastindex else match.group(0)
                url = url.strip().rstrip('/"\'')
                
                if not url.startswith('http'):
                    continue
                if 'github.com' in url or 'githubusercontent' in url:
                    continue
                if len(url) < 10:
                    continue
                
                # ========== 新增：检查是否为有效中转站 URL ==========
                if not self._is_valid_relay_url(url):
                    continue
                
                # 计算优先级
                priority = 0
                url_lower = url.lower()
                
                # 已知中转站域名优先级最高
                for relay_domain in KNOWN_RELAY_DOMAINS:
                    if relay_domain in url_lower:
                        priority += 5
                        break
                
                # 其他关键词
                for keyword in URL_PRIORITY_KEYWORDS:
                    if keyword in url_lower:
                        priority += 1
                
                found_urls.append((url, priority))
        
        if found_urls:
            found_urls.sort(key=lambda x: x[1], reverse=True)
            best_url = found_urls[0][0]
            best_url = re.sub(r'/v\d+/?$', '', best_url).rstrip('/')
            
            # 判断是否为中转站（非官方域名）
            is_relay = 'openai.com' not in best_url and 'azure.com' not in best_url
            
            return best_url, is_relay
        
        return config.default_base_urls.get(platform, ""), False
    
    def _extract_keys_from_content(self, content: str, source_url: str) -> List[ScanResult]:
        """
        从代码内容提取 Key
        
        优化：预过滤提前
        1. 先检查内存缓存（最快）
        2. 再检查数据库（提前丢弃已入库 Key，减轻验证队列压力）
        """
        results = []
        
        for platform, pattern in self._key_patterns.items():
            if platform == "azure":
                continue
            
            for match in pattern.finditer(content):
                api_key = match.group(0)
                
                # ========== 优化：预过滤提前 ==========
                # 1. 内存缓存检查（最快）
                if self._is_key_processed(api_key):
                    continue
                
                # 2. 数据库预检查（在任何其他处理前，提前丢弃已入库 Key）
                # 这一步可减轻下游验证队列压力
                key_exists = getattr(self.db, "key_exists_sync", self.db.key_exists)
                if key_exists(api_key):
                    self._mark_key_processed(api_key)
                    continue
                
                # 过滤检查
                should_skip, reason = self._should_skip_key(api_key)
                if should_skip:
                    self._mark_key_processed(api_key)
                    self.stats["skipped_entropy"] += 1
                    if self.dashboard:
                        self.dashboard.increment_stat("skipped_low_entropy")
                    self._log(f"Skip {mask_key(api_key)} ({reason})", "SKIP")
                    continue
                
                # 提取上下文
                context = self._extract_context(content, match.start())
                
                # 检查 Azure
                is_azure = self._is_azure_context(context)
                
                if is_azure:
                    azure_endpoint = self._extract_azure_endpoint(context)
                    base_url = azure_endpoint or ""
                    actual_platform = "azure"
                    is_relay = False
                else:
                    base_url, is_relay = self._extract_base_url(context, platform)
                    actual_platform = "relay" if is_relay else platform
                
                # URL 黑名单检查
                should_skip_url, url_reason = self._should_skip_url(base_url)
                if should_skip_url:
                    self._mark_key_processed(api_key)
                    self.stats["skipped_blacklist"] += 1
                    if self.dashboard:
                        self.dashboard.increment_stat("skipped_blacklist")
                    self._log(f"Skip {mask_key(api_key)} (URL: {url_reason})", "SKIP")
                    continue
                
                results.append(ScanResult(
                    platform=actual_platform,
                    api_key=api_key,
                    base_url=base_url,
                    source_url=source_url,
                    is_azure=is_azure,
                    is_relay=is_relay,
                    context=context
                ))
                
                self._mark_key_processed(api_key)
        
        return results
    
    # ========================================================================
    #                           搜索逻辑
    # ========================================================================
    
    def _handle_rate_limit(self) -> bool:
        """处理速率限制：优先切换到健康且仍有 code_search 配额的 token。"""
        index = self._current_client_index % len(self._github_clients)
        self._record_token_rate_limit(index, cooldown=60.0)
        self._mark_current_token_exhausted()
        self._apply_request_backoff(15.0, "rate_limit")
        if self._select_available_client():
            return True

        waits = [
            entry.get("disabled_until", 0) - time.time()
            for entry in self._token_quota.values()
            if entry.get("disabled_until", 0) > time.time()
        ]
        sleep_seconds = max(5, min(waits) if waits else 30)
        self._log(f"All token Code Search quota exhausted, waiting {sleep_seconds:.0f}s...", "WARN")
        while sleep_seconds > 0 and not self.stop_event.is_set():
            time.sleep(min(10, sleep_seconds))
            sleep_seconds -= 10
        return True

    def search_keyword(self, keyword: str) -> int:
        """Search a single code-search keyword and process matching files in batches."""
        found_count = 0
        current_index = self._current_client_index % len(self._github_clients) if self._github_clients else 0
        score, source_type, _reasons = score_search_keyword(keyword)

        if self.dashboard:
            self.dashboard.update_stats(
                current_keyword=keyword,
                current_token_index=self._current_client_index,
                total_tokens=len(self._github_clients),
            )
            self.dashboard.mark_source_activity(
                "code_search",
                source_type=source_type,
                source_score=float(score),
                target=keyword,
                keyword=keyword,
                budget_total=getattr(self, "_keyword_budget", 0),
            )

        try:
            self._wait_for_request_backoff()
            self._log(f'Searching "{keyword}"...', "SCAN")

            query = keyword if any(marker in keyword for marker in ["filename:", "path:", "language:"]) else f"{keyword} in:file"
            if not self._select_available_client():
                self._handle_rate_limit()
                return found_count

            current_index = self._current_client_index % len(self._github_clients)
            client = self._get_github_client()
            code_results = client.search_code(query)
            self._record_token_success(current_index)
            self._relax_request_backoff()

            batch_size = 40
            files_batch = []

            for i, code_file in enumerate(code_results):
                if i >= self._max_results_per_keyword:
                    self._log(f'Result cap reached for keyword: {self._max_results_per_keyword}', "INFO")
                    break
                if self.stop_event.is_set():
                    break

                try:
                    file_sha = getattr(code_file, "sha", None)
                    if file_sha and self._is_sha_processed(file_sha):
                        self.stats["skipped_sha"] += 1
                        if self.dashboard:
                            self.dashboard.increment_stat("skipped_sha")
                            self.dashboard.mark_source_activity("code_search", skipped={"skipped_sha": 1})
                        continue

                    file_path = getattr(code_file, "path", "") or ""
                    file_size = getattr(code_file, "size", 0) or 0
                    skip_file, _skip_reason = should_skip_file(file_path, file_size)
                    if skip_file:
                        self.stats["skipped_file_filter"] += 1
                        if self.dashboard:
                            self.dashboard.increment_stat("skipped_file_filter")
                            self.dashboard.mark_source_activity("code_search", skipped={"skipped_file_filter": 1})
                        if file_sha:
                            self._mark_sha_processed(file_sha)
                        continue

                    raw_url = code_file.download_url
                    html_url = code_file.html_url
                    if file_sha:
                        self._mark_sha_processed(file_sha)

                    if raw_url:
                        files_batch.append((raw_url, html_url, code_file))
                    else:
                        try:
                            content = code_file.decoded_content.decode("utf-8", errors="ignore")
                            found_count += self._process_downloaded_file(html_url, content, found_count)
                        except Exception:
                            logger.debug("decoded_content_fallback_failed")

                    if len(files_batch) >= batch_size:
                        found_count += self._process_file_batch(files_batch)
                        files_batch = []
                        self._rotate_client()
                        if self.dashboard:
                            self.dashboard.update_stats(current_token_index=self._current_client_index)

                except Exception as exc:
                    logger.debug(f"scan_item_error: {type(exc).__name__}: {exc}")
                    continue

            if files_batch:
                found_count += self._process_file_batch(files_batch)

        except RateLimitExceededException:
            self._log("Rate limit hit, rotating token...", "WARN")
            self._handle_rate_limit()
        except GithubException as exc:
            error_text = str(exc).lower()
            is_rate_limited = (
                "rate limit" in error_text
                or "api rate limit exceeded" in error_text
                or getattr(exc, "status", None) == 403
            )
            if is_rate_limited:
                self._log("Code Search quota exhausted, waiting for next token/reset", "WARN")
                self._handle_rate_limit()
            else:
                self._record_token_failure(current_index, reason=f"github:{getattr(exc, 'status', 'error')}", cooldown=20.0)
                self._apply_request_backoff(8.0, "github_error")
                self._log(f"API error: {str(exc)[:60]}", "ERROR")
                self._rotate_client()
        except Exception as exc:
            self._record_token_failure(current_index, reason=type(exc).__name__, cooldown=10.0)
            self._apply_request_backoff(5.0, type(exc).__name__)
            self._log(f"Search error: {str(exc)[:60]}", "ERROR")
            self._rotate_client()

        return found_count

    def _process_file_batch(self, files_batch: List[Tuple[str, str, any]]) -> int:
        """Download and process a batch of candidate files."""
        found_count = 0
        downloaded_files = self._run_async_download(files_batch)

        for html_url, content, code_file in downloaded_files:
            found_count += self._process_downloaded_file(html_url, content, found_count)

        downloaded_urls = {item[0] for item in downloaded_files}
        for raw_url, html_url, code_file in files_batch:
            if html_url not in downloaded_urls:
                try:
                    content = code_file.decoded_content.decode("utf-8", errors="ignore")
                    found_count += self._process_downloaded_file(html_url, content, found_count)
                except Exception as exc:
                    logger.debug(f"fallback_decode_error: {type(exc).__name__}")

        return found_count

    def _process_downloaded_file(self, source_url: str, content: str, current_count: int) -> int:
        """Extract candidate keys from one downloaded file."""
        found_count = 0
        self.stats["files_scanned"] += 1
        if self.dashboard:
            self.dashboard.increment_stat("total_scanned")
            self.dashboard.mark_source_activity("code_search", files_scanned=1)

        results = self._extract_keys_from_content(content, source_url)

        for result in results:
            try:
                self.result_queue.put(result, timeout=5)
            except Exception as exc:
                logger.debug(f"result_queue_error: {type(exc).__name__}")
            found_count += 1
            self.stats["total_found"] += 1

            if self.dashboard:
                self.dashboard.increment_stat("total_keys_found")
                self.dashboard.increment_source_found("code_search")
                self.dashboard.mark_source_activity("code_search", keys_found=1)
                self.dashboard.add_log(
                    f"Found {result.platform.upper()} key: {mask_key(result.api_key)}",
                    "FOUND",
                )

        return found_count

    def run(self, resume: bool = False):
        """Run the scanner main loop with a bounded keyword budget."""
        round_num = 0
        keywords = config.get_scheduled_search_keywords()
        total_keywords = len(keywords)
        keyword_budget = min(total_keywords, int(os.getenv("CODE_SEARCH_KEYWORD_BUDGET", "8"))) if total_keywords else 0
        self._keyword_budget = keyword_budget

        if self.dashboard and keywords:
            top_keywords = keywords[: min(keyword_budget or 5, 5)]
            self._log("Top priority keywords: " + " | ".join(top_keywords), "INFO")

        start_index = 0
        if resume and keyword_budget:
            progress = self.db.load_progress()
            if progress["total"] == keyword_budget and not progress["is_completed"]:
                start_index = progress["current_index"]
                self._log(f"Resuming from keyword {start_index + 1}/{keyword_budget}", "INFO")
            else:
                self._log("No matching resume checkpoint found, starting from the beginning", "INFO")

        while not self.stop_event.is_set():
            round_num += 1
            scan_run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + f"-r{round_num}"
            if self.dashboard and hasattr(self.dashboard, "start_scan_run"):
                self.dashboard.start_scan_run(scan_run_id, round_num, keyword_budget)
                self.dashboard.update_stats(search_budget_total=keyword_budget, search_budget_used=0)
            self._log(f"SCAN_RUN_START {scan_run_id} round {round_num}, keywords {keyword_budget}/{total_keywords}", "SCAN")

            if keyword_budget == 0:
                self._log("No scheduled code-search keywords available", "WARN")
                time.sleep(30)
                continue

            for i, keyword in enumerate(keywords[:keyword_budget]):
                if self.stop_event.is_set():
                    break
                if round_num == 1 and i < start_index:
                    continue

                score, source_type, _reasons = score_search_keyword(keyword)
                if self.dashboard:
                    self.dashboard.update_stats(
                        round_keyword_index=i + 1,
                        round_total_keywords=keyword_budget,
                        search_budget_used=i + 1,
                    )
                    self.dashboard.mark_source_activity(
                        "code_search",
                        source_type=source_type,
                        source_score=float(score),
                        target=keyword,
                        keyword=keyword,
                        budget_total=keyword_budget,
                    )

                found_count = self.search_keyword(keyword)
                if self.dashboard and hasattr(self.dashboard, "_record_query_quality"):
                    self.dashboard._record_query_quality(keyword, scanned=1, found=found_count, valid=0)

                self.db.save_progress(i + 1, keyword_budget, is_completed=(i + 1 == keyword_budget))

                if not self.stop_event.is_set():
                    time.sleep(0.5)

            self.db.save_progress(keyword_budget, keyword_budget, is_completed=True)

            if not self.stop_event.is_set():
                self._log(f"Round {round_num} complete, waiting 2 minutes...", "INFO")
                for _ in range(12):
                    if self.stop_event.is_set():
                        break
                    time.sleep(10)
                self.db.reset_progress()


def start_scanner(
    result_queue: queue.Queue,
    db: Database,
    stop_event: threading.Event,
    dashboard = None,
    resume: bool = False
) -> threading.Thread:
    """
    启动扫描器线程
    
    Args:
        resume: 是否从断点续传
    """
    scanner = GitHubScanner(result_queue, db, stop_event, dashboard)
    thread = threading.Thread(target=lambda: scanner.run(resume=resume), name="GitHubScanner", daemon=True)
    thread.start()
    return thread
