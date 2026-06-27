"""
配置模块 - 集中管理所有配置项

本模块提供：
- 代理配置（必需，中国大陆环境）
- GitHub Token 池（多 Token 轮询）
- 正则表达式库
- 平台默认 URL
"""

import os
import importlib.util
import random
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, FrozenSet, TypedDict


class QueryTemplateSpec(TypedDict, total=False):
    template: str
    structural: List[str]
    core: List[str]
    context: List[str]
    negative: List[str]


# ============================================================================
#                          熍断器配置 (Circuit Breaker)
# ============================================================================

# 受保护域名白名单 - 永远不会被熍断
PROTECTED_DOMAINS: FrozenSet[str] = frozenset({
    # 官方 API
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    # Azure 域名后缀
    "openai.azure.com",
    # GitHub 文件下载
    "github.com",
    "raw.githubusercontent.com",
})

# 应用层错误 HTTP 状态码 - 不触发熍断（说明服务器连通性正常）
SAFE_HTTP_STATUS_CODES: FrozenSet[int] = frozenset({
    400,  # Bad Request - 请求格式错误
    401,  # Unauthorized - Key 无效
    403,  # Forbidden - 权限不足
    404,  # Not Found - 端点不存在
    422,  # Unprocessable Entity - 请求参数错误
    429,  # Rate Limit - 被限流
})

# 网关错误 HTTP 状态码 - 触发熍断（说明服务不可用）
CIRCUIT_BREAKER_HTTP_CODES: FrozenSet[int] = frozenset({
    502,  # Bad Gateway
    503,  # Service Unavailable
    504,  # Gateway Timeout
})

# 熍断器参数
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5   # 连续失败次数阈值
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 60   # 熍断恢复时间（秒）
CIRCUIT_BREAKER_HALF_OPEN_REQUESTS = 3  # 半开状态允许的试探请求数


# ============================================================================
#                              正则表达式库
# ============================================================================

REGEX_PATTERNS = {
    # ============================================================================
    #                          主流 AI 平台 (高优先级)
    # ============================================================================

    # OpenAI: 标准 key (sk-xxx) 和 project key (sk-proj-xxx)
    # 新格式: sk-proj-xxx (项目 Key), sk-svcacct-xxx (服务账户)
    "openai": r'(?<!example_)(?<!test_)(?<!demo_)(?<!fake_)(?<!sample_)(?<!dev_)(?<!staging_)sk-(?:proj-|svcacct-)?(?!(?:placeholder|example|test|demo|your|xxx|fake|sample|dev|staging|sandbox|xxxxxx|abcdef|123456|insert|replace))[a-zA-Z0-9\-_]{20,}',

    # Google Gemini / Google AI Studio: AIza 开头，39 字符
    "gemini": r'(?<!test)(?<!example)(?<!sample)(?<!dev)AIza[0-9A-Za-z\-_]{35}',

    # Anthropic Claude: sk-ant- 开头
    "anthropic": r'(?<!example_)(?<!test_)(?<!dev_)(?<!staging_)sk-ant-(?!(?:api0|xxx|test|demo|example|sample|dev|staging|sandbox|placeholder))[a-zA-Z0-9\-_]{20,}',

    # Azure OpenAI: 32位十六进制
    "azure": r'(?<![a-f0-9])(?!0{32})(?!f{32})(?!a{32})(?!e{32})[a-f0-9]{32}(?![a-f0-9])',

    # ============================================================================
    #                          新兴 AI 平台 (中优先级)
    # ============================================================================

    # HuggingFace: hf_ 开头
    "huggingface": r'hf_[a-zA-Z0-9]{34,}',

    # Groq: gsk_ 开头，52字符
    "groq": r'gsk_[a-zA-Z0-9]{52}',

    # DeepSeek: sk- 开头，48+ 字符 (与 OpenAI 区分靠长度)
    "deepseek": r'sk-[a-zA-Z0-9]{48,}',

    # Zhipu GLM / BigModel: 常见为 32 位 id + 16 位 secret 的复合 key
    "glm": r'(?<![A-Za-z0-9])(?!(?:0{32}\\.[A-Za-z0-9]{16}|[A-Za-z0-9]{32}\\.0{16}))[A-Za-z0-9]{32}\\.[A-Za-z0-9]{16}(?![A-Za-z0-9])',

    # MiniMax: 常见为 sk- 开头的长 token，结合 minimax/abab 上下文识别
    "minimax": r'sk-(?!(?:test|demo|example|sample|fake|dev|staging))[A-Za-z0-9]{32,}(?=.*(?:minimax|abab))',

    # Kimi / Moonshot: 常见为 sk- 开头的长 token，结合 moonshot/kimi 上下文识别
    "kimi": r'sk-(?!(?:test|demo|example|sample|fake|dev|staging))[A-Za-z0-9]{32,}(?=.*(?:moonshot|kimi))',

    # Cohere: 40字符 Base64
    "cohere": r'(?<!test)(?<!example)[a-zA-Z0-9]{40}(?=.*cohere)',

    # Mistral AI: 32字符
    "mistral": r'(?<!test)(?<!example)[a-zA-Z0-9]{32}(?=.*mistral)',

    # Together AI: 64字符十六进制
    "together": r'[a-f0-9]{64}(?=.*together)',

    # Replicate: r8_ 开头
    "replicate": r'r8_[a-zA-Z0-9]{37,}',

    # Perplexity: pplx- 开头
    "perplexity": r'pplx-[a-zA-Z0-9]{48,}',

    # Fireworks AI: fw_ 开头
    "fireworks": r'fw_[a-zA-Z0-9]{40,}',

    # Anyscale: esecret_ 开头
    "anyscale": r'esecret_[a-zA-Z0-9]{40,}',

    # ============================================================================
    #                          云服务商 API (低优先级)
    # ============================================================================

    # AWS Access Key: AKIA 开头，20字符
    "aws_access_key": r'AKIA[0-9A-Z]{16}',

    # AWS Secret Key: 40字符 Base64
    "aws_secret_key": r'(?<!test)(?<!example)[A-Za-z0-9/+=]{40}(?=.*(?:aws|secret|key))',

    # GitHub Token: ghp_, gho_, ghu_, ghs_, ghr_ 开头
    "github_token": r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}',

    # Stripe: sk_live_ 或 rk_live_ 开头
    "stripe": r'(?:sk|rk)_live_[a-zA-Z0-9]{24,}',

    # Twilio: SK 开头，32字符
    "twilio": r'SK[a-f0-9]{32}',

    # SendGrid: SG. 开头
    "sendgrid": r'SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{22,}',

    # Slack: xox[baprs]- 开头
    "slack": r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}',

    # Discord Bot Token
    "discord": r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',

    # Telegram Bot Token
    "telegram": r'\d{8,10}:[a-zA-Z0-9_-]{35}',
}

# Azure 特征识别正则
AZURE_URL_PATTERN = r'https://[\w\-]+\.openai\.azure\.com'
AZURE_CONTEXT_KEYWORDS = ['azure', 'openai.azure.com', 'azure_endpoint', 'AZURE_OPENAI']

# Base URL 提取正则（用于上下文感知）
BASE_URL_PATTERNS = [
    # 带变量名的 URL 赋值
    r'(?:base_url|api_base|OPENAI_API_BASE|OPENAI_BASE_URL|host|endpoint|api_endpoint|API_URL|proxy_url|PROXY)\s*[=:]\s*["\']?(https?://[^\s"\'<>]+)["\']?',
    # 通用 HTTP URL
    r'(https?://[a-zA-Z0-9\-_.]+(?::\d+)?(?:/[a-zA-Z0-9\-_./]*)?)',
]

# URL 关键词优先级（用于排序提取到的 URL）
URL_PRIORITY_KEYWORDS = ['base', 'api', 'host', 'endpoint', 'proxy', 'openai', 'relay']


@lru_cache(maxsize=512)
def score_search_keyword(keyword: str) -> tuple[int, str, tuple[str, ...]]:
    """Score a GitHub search keyword so higher-value tasks run first."""
    normalized = " ".join(keyword.lower().split())
    score = 0
    reasons: List[str] = []

    def bump(points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(reason)

    # Strong, high-signal targets first.
    if any(marker in normalized for marker in (
        'filename:.env',
        'filename:.env.local',
        'filename:.env.production',
        'filename:.env.prod',
        'filename:secrets',
        'filename:config',
    )):
        bump(30, 'secret-file')

    if any(marker in normalized for marker in (
        'openai_api_key',
        'anthropic_api_key',
        'gemini_api_key',
        'sk-proj-',
        'sk-ant-',
        'hf_',
        'gsk_',
        'ghp_',
        'glpat-',
    )):
        bump(28, 'strong-secret')

    if any(marker in normalized for marker in (
        'base_url',
        'openai_base_url',
        'endpoint',
        'relay',
        'one-api',
        'new-api',
    )):
        bump(16, 'relay-context')

    if 'filename:' in normalized:
        bump(14, 'filename-scope')

    if 'language:' in normalized:
        bump(5, 'language-scope')

    if any(marker in normalized for marker in ('repo:', 'org:', 'user:')):
        bump(10, 'repo-scope')

    if any(marker in normalized for marker in ('not test', 'not example', 'not demo', 'not mock', 'not staging')):
        bump(6, 'noise-filter')

    # Broader, less precise queries are still useful but should run later.
    if 'sk-' in normalized and 'filename:' not in normalized:
        bump(12, 'key-signal')

    if any(marker in normalized for marker in ('openai', 'anthropic', 'gemini', 'azure', 'relay', 'one-api', 'new-api')):
        bump(8, 'platform-signal')

    if normalized.count('not ') >= 2:
        bump(4, 'multi-exclusion')

    if len(normalized.split()) <= 2:
        bump(3, 'short-query')

    if score >= 60:
        bucket = 'p0'
    elif score >= 35:
        bucket = 'p1'
    elif score >= 18:
        bucket = 'p2'
    else:
        bucket = 'p3'

    return score, bucket, tuple(reasons)


# ============================================================================
#                              配置类
# ============================================================================

@dataclass
class Config:
    """
    全局配置类
    
    重要配置项：
    - proxy_url: 代理地址（中国大陆必需）
    - github_tokens: GitHub Token 列表
    """
    
    # ==================== 代理配置 ====================
    # 直连模式（无代理）
    # 如需代理，可设置环境变量 PROXY_URL 或直接修改此处
    proxy_url: str = field(
        default_factory=lambda: os.getenv("PROXY_URL", "")  # 直连模式
    )
    proxy_urls: List[str] = field(default_factory=lambda: [
        item.strip() for item in os.getenv("PROXY_POOL_URLS", "").split(",") if item.strip()
    ])
    dynamic_proxy_source_url: str = field(
        default_factory=lambda: os.getenv("DYNAMIC_PROXY_SOURCE_URL", "")
    )
    
    # ==================== GitHub Token 池 ====================
    # 多 Token 轮询可有效规避速率限制
    # 未认证: 10次/分钟, 认证: 30次/分钟
    # 多个 Token 可大幅提升扫描速度
    # 
    # 配置方式：
    # 1. 直接在此列表中添加 token（不推荐，易泄露）
    # 2. 设置环境变量 GITHUB_TOKENS（推荐，用逗号分隔多个token）
    # 3. 创建 config_local.py 覆盖此配置（推荐）
    github_tokens: List[str] = field(default_factory=lambda: (
        # 优先从环境变量读取
        os.getenv("GITHUB_TOKENS", "").split(",") if os.getenv("GITHUB_TOKENS") else [
            # ===== 默认为空，请通过环境变量或 config_local.py 配置 =====
            # 示例格式：
            # "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            # "ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
        ]
    ))
    
    # Token 轮询索引
    _token_index: int = 0
    
    # ==================== 数据库配置 ====================
    db_path: str = "leaked_keys.db"

    # ==================== Pastebin 配置 ====================
    # Pastebin Pro API Key (可选，用于 Scraping API)
    # 免费用户可以不配置，但扫描效率较低
    pastebin_api_key: str = field(
        default_factory=lambda: os.getenv("PASTEBIN_API_KEY", "")
    )
    
    # ==================== 线程配置 ====================
    consumer_threads: int = 20  # 验证器线程数（IO 密集型，可开多）
    
    # ==================== 网络配置 ====================
    request_timeout: int = 15  # HTTP 请求超时（秒）

    # ==================== Redis 配置 ====================
    # Redis 持久化缓存地址（可选）
    # 设置后 L1/L2/L3 缓存自动持久化到 Redis，跨启动生效
    # 格式: redis://localhost:6379/0
    redis_url: str = field(
        default_factory=lambda: os.getenv('REDIS_URL', '')
    )

    # ==================== Provider 白名单 ====================
    # 默认只启用用户当前关注的 provider。
    # 其他 provider 的正则、关键词和扫描源不会参与本轮扫描，避免额外消耗 GitHub Code Search 配额。
    enabled_providers: List[str] = field(default_factory=lambda: [
        item.strip().lower()
        for item in os.getenv("ENABLED_PROVIDERS", "openai,deepseek,glm,minimax,kimi").split(",")
        if item.strip()
    ])
    
    # ==================== 熍断器配置 ====================
    circuit_breaker_enabled: bool = True  # 是否启用熍断器
    
    # ==================== 扫描配置 ====================
    context_window: int = 10  # 上下文窗口（前后各 N 行）
    
    # 搜索词槽与模板 - 用于受控生成布尔查询图
    query_vocab: Dict[str, List[str]] = field(default_factory=lambda: {
        "core_signals": [
            "OPENAI_API_KEY",
            "sk-proj-",
            "sk-",
            "ANTHROPIC_API_KEY",
            "OPENAI_BASE_URL",
            "DEEPSEEK_API_KEY",
            "BIGMODEL_API_KEY",
            "MINIMAX_API_KEY",
            "MOONSHOT_API_KEY",
        ],
        "context_signals": [
            "base_url",
            "endpoint",
            "proxy",
            "deepseek",
            "bigmodel",
            "glm",
            "minimax",
            "moonshot",
            "kimi",
        ],
        "structural_signals": [
            "filename:.env",
            "filename:.env.local",
            "filename:.env.production",
            "filename:secrets.yaml",
            "filename:secrets.json",
            "filename:config.json",
            "filename:config.py",
            "language:python",
            "language:javascript",
        ],
        "negative_terms": [
            "NOT test",
            "NOT example",
            "NOT demo",
            "NOT mock",
            "NOT staging",
            "NOT sandbox",
        ],
    })

    query_templates: Dict[str, List[QueryTemplateSpec]] = field(default_factory=lambda: {
        "strong_precision": [
            {
                "template": "{structural} {core} {negative}",
                "structural": ["filename:.env", "filename:.env.local", "filename:.env.production"],
                "core": ["OPENAI_API_KEY", "DEEPSEEK_API_KEY", "BIGMODEL_API_KEY", "MINIMAX_API_KEY", "MOONSHOT_API_KEY"],
                "negative": ["NOT staging NOT sandbox NOT example", "NOT test NOT example"],
            },
            {
                "template": "{structural} {core} {negative}",
                "structural": ["filename:secrets.yaml", "filename:secrets.json", "filename:config.json"],
                "core": ["openai_api_key", "deepseek_api_key", "bigmodel_api_key", "minimax_api_key", "moonshot_api_key"],
                "negative": ["NOT example", "NOT test NOT example"],
            },
        ],
        "medium_recall": [
            {
                "template": "{core} {structural} {negative}",
                "core": ["sk-proj-", "sk-", "chatglm", "moonshot", "minimax"],
                "structural": ["language:python", "language:javascript"],
                "negative": ["NOT test NOT example NOT mock", "NOT test NOT example NOT mock NOT staging"],
            },
            {
                "template": "{core} {context} {negative}",
                "core": ["sk-", "OPENAI_API_KEY="],
                "context": ["deepseek", "bigmodel", "chatglm", "glm-4", "minimax", "abab", "moonshot", "kimi"],
                "negative": ["NOT test NOT demo NOT example", "NOT test NOT example NOT staging"],
            },
        ],
        "low_frequency": [
            {
                "template": "{structural} {context} {negative}",
                "structural": ["filename:config.py"],
                "context": ["DEEPSEEK_API_KEY", "BIGMODEL_API_KEY", "MINIMAX_API_KEY", "MOONSHOT_API_KEY", "endpoint", "proxy"],
                "negative": ["NOT test", "NOT example"],
            },
        ],
    })
    
    # 搜索关键词兼容层：保留旧入口，供已有代码和外部脚本继续使用
    search_keywords: List[str] = field(default_factory=list)

    # ==================== 平台默认 URL ====================
    default_base_urls: Dict[str, str] = field(default_factory=lambda: {
        # 主流 AI 平台
        "openai": "https://api.openai.com",
        "gemini": "https://generativelanguage.googleapis.com/v1beta",
        "anthropic": "https://api.anthropic.com",
        "azure": "",
        # 新兴 AI 平台
        "huggingface": "https://api-inference.huggingface.co",
        "groq": "https://api.groq.com/openai/v1",
        "deepseek": "https://api.deepseek.com",
        "glm": "https://open.bigmodel.cn/api/paas/v4",
        "minimax": "https://api.minimax.chat/v1",
        "kimi": "https://api.moonshot.cn/v1",
        "cohere": "https://api.cohere.ai/v1",
        "mistral": "https://api.mistral.ai/v1",
        "together": "https://api.together.xyz/v1",
        "replicate": "https://api.replicate.com/v1",
        "perplexity": "https://api.perplexity.ai",
        "fireworks": "https://api.fireworks.ai/inference/v1",
        "anyscale": "https://api.endpoints.anyscale.com/v1",
        # 云服务商
        "aws_access_key": "",
        "aws_secret_key": "",
        "github_token": "https://api.github.com",
        "stripe": "https://api.stripe.com",
        "twilio": "https://api.twilio.com",
        "sendgrid": "https://api.sendgrid.com",
        "slack": "https://slack.com/api",
        "discord": "https://discord.com/api",
        "telegram": "https://api.telegram.org",
    })
    
    @property
    def proxies(self) -> Optional[Dict[str, str]]:
        """返回 requests 代理格式"""
        if self.proxy_url:
            return {"http": self.proxy_url, "https": self.proxy_url}
        return None

    def proxy_pool_urls(self) -> List[str]:
        """返回代理池地址列表"""
        return list(self.proxy_urls)

    def proxy_pool_urls(self) -> List[str]:
        """返回代理池地址列表"""
        return list(self.proxy_urls)
    
    def get_token(self) -> str:
        """获取当前 Token"""
        if not self.github_tokens:
            return ""
        return self.github_tokens[self._token_index % len(self.github_tokens)]
    
    def rotate_token(self) -> str:
        """轮换到下一个 Token"""
        if not self.github_tokens:
            return ""
        self._token_index = (self._token_index + 1) % len(self.github_tokens)
        return self.github_tokens[self._token_index]
    
    def get_random_token(self) -> str:
        """随机获取一个 Token"""
        if not self.github_tokens:
            return ""
        return random.choice(self.github_tokens)

    def get_scheduled_search_keywords(self) -> List[str]:
        """Expand template-driven boolean query graphs, dedupe them, then return high-value queries first."""
        ordered_groups = ["strong_precision", "medium_recall", "low_frequency"]
        expanded: List[str] = []
        seen = set()

        for group in ordered_groups:
            for spec in self.query_templates.get(group, []):
                template = str(spec.get("template", "")).strip()
                if not template:
                    continue

                structural_terms: List[str] = spec.get("structural") or [""]
                core_terms: List[str] = spec.get("core") or [""]
                context_terms: List[str] = spec.get("context") or [""]
                negative_terms: List[str] = spec.get("negative") or [""]

                max_queries = 12 if group == "strong_precision" else 10 if group == "medium_recall" else 6
                produced = 0

                for structural in structural_terms:
                    for core in core_terms:
                        for context in context_terms:
                            for negative in negative_terms:
                                query = template.format(
                                    structural=structural,
                                    core=core,
                                    context=context,
                                    negative=negative,
                                )
                                query = " ".join(query.split())
                                if not query or query in seen:
                                    continue
                                seen.add(query)
                                expanded.append(query)
                                produced += 1
                                if produced >= max_queries:
                                    break
                            if produced >= max_queries:
                                break
                        if produced >= max_queries:
                            break
                    if produced >= max_queries:
                        break

        # Backward compatibility: allow ad-hoc legacy keywords to append if present.
        for keyword in self.search_keywords:
            normalized = " ".join(keyword.split())
            if normalized in seen:
                continue
            seen.add(normalized)
            expanded.append(keyword)

        scored = []
        for keyword in expanded:
            score, bucket, _reasons = score_search_keyword(keyword)
            scored.append((score, bucket, keyword))

        bucket_order = {"p0": 0, "p1": 1, "p2": 2, "p3": 3}
        scored.sort(key=lambda item: (-item[0], bucket_order.get(item[1], 99), item[2]))
        return [keyword for _, _, keyword in scored]
    
    @property
    def enabled_detector_platforms(self) -> Set[str]:

        platforms = set(self.enabled_providers)
        if platforms.intersection({"relay", "oneapi", "newapi", "openai"}):
            platforms.add("openai")
        return platforms

    def filter_platform_map(self, values: Dict[str, str]) -> Dict[str, str]:
        """过滤正则/default url 等 platform 映射。"""
        allowed = self.enabled_detector_platforms
        return {key: value for key, value in values.items() if key.lower() in allowed}


# 全局配置实例
config = Config()

# ============================================================================
#                          本地配置覆盖 (config_local.py)
# ============================================================================
def _load_local_config_namespace() -> dict:
    config_path = os.getenv("CONFIG_PATH", os.path.join(os.path.dirname(__file__), "config_local.py"))
    if not os.path.isfile(config_path):
        return {}
    spec = importlib.util.spec_from_file_location("config_local_runtime", config_path)
    if not spec or not spec.loader:
        return {}
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {name: getattr(module, name) for name in dir(module) if name.isupper()}


try:
    local_config = _load_local_config_namespace()

    if 'GITHUB_TOKENS' in local_config:
        config.github_tokens = local_config['GITHUB_TOKENS']

    if local_config.get('PROXY_URL'):
        config.proxy_url = local_config['PROXY_URL']
    if local_config.get('DYNAMIC_PROXY_SOURCE_URL'):
        config.dynamic_proxy_source_url = local_config['DYNAMIC_PROXY_SOURCE_URL']
    if 'PROXY_POOL_URLS' in local_config:
        config.proxy_urls = list(local_config['PROXY_POOL_URLS'] or [])

    if 'DB_PATH' in local_config:
        config.db_path = local_config['DB_PATH']
    if 'CONSUMER_THREADS' in local_config:
        config.consumer_threads = local_config['CONSUMER_THREADS']
    if 'REQUEST_TIMEOUT' in local_config:
        config.request_timeout = local_config['REQUEST_TIMEOUT']
    if 'CONTEXT_WINDOW' in local_config:
        config.context_window = local_config['CONTEXT_WINDOW']
    if 'MAX_CONCURRENCY' in local_config:
        config.max_concurrency = local_config['MAX_CONCURRENCY']
    if 'REDIS_URL' in local_config:
        config.redis_url = local_config['REDIS_URL']
    if 'CIRCUIT_BREAKER_ENABLED' in local_config:
        config.circuit_breaker_enabled = local_config['CIRCUIT_BREAKER_ENABLED']
    if 'ENABLED_PROVIDERS' in local_config:
        config.enabled_providers = list(local_config['ENABLED_PROVIDERS'] or [])
    if 'SEARCH_KEYWORDS' in local_config:
        config.search_keywords = list(local_config['SEARCH_KEYWORDS'] or [])
    if 'PASTEBIN_API_KEY' in local_config:
        config.pastebin_api_key = local_config['PASTEBIN_API_KEY']

    if local_config:
        print(f"[OK] 已加载本地配置文件 {os.getenv('CONFIG_PATH', 'config_local.py')}")
    elif not config.github_tokens or not any(config.github_tokens):
        print("[WARNING] 警告: 未配置 GitHub Tokens！")
        print("   请创建 config_local.py 文件或设置环境变量 GITHUB_TOKENS")
        print("   参考: config_local.py.example")
except Exception as e:
    print(f"[WARNING] 加载本地配置时出错: {e}")

# 按 provider 白名单收敛 detector/default url，避免其他 provider 被额外源或提取逻辑误启用。
REGEX_PATTERNS = config.filter_platform_map(REGEX_PATTERNS)
config.default_base_urls = config.filter_platform_map(config.default_base_urls)
