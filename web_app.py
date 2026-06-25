import json
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from proxy_pool import get_proxy_pool
from config import config as scanner_config

DB_PATH = "/app/data/leaked_keys.db"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "web" / "static"
INDEX_FILE = STATIC_DIR / "index.html"
SESSION_COOKIE = "scanner_panel_session"
PANEL_USERNAME = os.getenv("PANEL_USERNAME", "admin")
PANEL_PASSWORD = os.getenv("PANEL_PASSWORD", "change-me-now")
SCANNER_LOG_PATH = Path(os.getenv("SCANNER_LOG_PATH", "/app/output/scanner.log"))
RUNTIME_STATE_PATH = Path(os.getenv("RUNTIME_STATE_PATH", "/app/output/runtime_state.json"))
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", str(BASE_DIR / "config_local.py")))
GITHUB_TOKENS = [token.strip() for token in os.getenv("GITHUB_TOKENS", "").split(",") if token.strip()]
PANEL_SESSIONS: dict[str, str] = {}
CN_TZ = timezone(timedelta(hours=8))

app = FastAPI(title="GitHub Secret Scanner Panel", version="2.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro&immutable=1", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def get_current_user(request: Request) -> str:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or token not in PANEL_SESSIONS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="未登录")
    return PANEL_SESSIONS[token]


def mask_key(api_key: str) -> str:
    if not api_key:
        return ""
    if len(api_key) <= 18:
        return api_key
    return api_key[:10] + "..." + api_key[-4:]


def format_bj_now() -> str:
    return datetime.now(CN_TZ).strftime("%Y-%m-%d %H:%M:%S")


def format_bj_timestamp(text: str) -> str:
    try:
        dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return text


def read_log_lines(limit: int = 200) -> list[str]:
    if not SCANNER_LOG_PATH.exists() or not SCANNER_LOG_PATH.is_file():
        return []
    with SCANNER_LOG_PATH.open("r", encoding="utf-8", errors="replace") as handle:
        raw_lines = handle.readlines()

    parsed = []
    for line in raw_lines[-limit:]:
        text = line.rstrip("\n")
        try:
            payload = json.loads(text)
            parsed.append(payload.get("log", text))
        except json.JSONDecodeError:
            parsed.append(text)
    return parsed


def read_runtime_state() -> dict:
    if not RUNTIME_STATE_PATH.exists() or not RUNTIME_STATE_PATH.is_file():
        return {}
    try:
        return json.loads(RUNTIME_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}




def get_proxy_pool_stats() -> dict:
    pool = get_proxy_pool()
    if not pool:
        return {"enabled": False, "total": 0, "healthy": 0, "unhealthy": 0, "proxies": []}
    return {"enabled": True, **pool.get_stats()}

def get_github_quota() -> list[dict]:
    results = []
    try:
        with get_conn() as conn:
            result_rows = conn.execute(
                """
                SELECT token_index, remaining, limit_value, reset_at, disabled_until,
                       last_checked, last_error, success_count, failure_count,
                       rate_limit_count, health_score, last_success_at
                FROM github_token_quota
                ORDER BY token_index ASC
                """
            ).fetchall()
        quota_state = {
            int(row["token_index"]): {
                "remaining": row["remaining"],
                "limit": row["limit_value"],
                "reset": row["reset_at"],
                "disabled_until": row["disabled_until"],
                "last_checked": row["last_checked"],
                "last_error": row["last_error"],
                "success_count": row["success_count"],
                "failure_count": row["failure_count"],
                "rate_limit_count": row["rate_limit_count"],
                "health_score": row["health_score"],
                "last_success_at": row["last_success_at"],
            }
            for row in result_rows
        }
    except Exception:
        quota_state = {}

    for index, token in enumerate(GITHUB_TOKENS, start=1):
        entry = quota_state.get(index, {})
        try:
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "github-api-scan-panel",
            }
            request = urllib.request.Request("https://api.github.com/rate_limit", headers=headers)
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
            user_request = urllib.request.Request("https://api.github.com/user", headers=headers)
            with urllib.request.urlopen(user_request, timeout=10) as response:
                user_payload = json.loads(response.read().decode("utf-8"))
            resources = payload.get("resources", {})
            code_search = resources.get("code_search", {})
            core = resources.get("core", {})
            reset_ts = code_search.get("reset")
            reset_at = None
            reset_at_bj = None
            if reset_ts:
                reset_dt_bj = datetime.fromtimestamp(reset_ts, tz=timezone.utc).astimezone(CN_TZ)
                reset_at = reset_dt_bj.isoformat()
                reset_at_bj = reset_dt_bj.strftime("%Y-%m-%d %H:%M:%S")
            disabled_until = float(entry.get("disabled_until") or 0.0)
            disabled_until_bj = None
            if disabled_until:
                disabled_until_bj = datetime.fromtimestamp(disabled_until, tz=timezone.utc).astimezone(CN_TZ).strftime("%Y-%m-%d %H:%M:%S")
            results.append(
                {
                    "token_index": index,
                    "user_id": user_payload.get("id"),
                    "login": user_payload.get("login"),
                    "code_search_limit": code_search.get("limit"),
                    "code_search_remaining": code_search.get("remaining"),
                    "code_search_used": code_search.get("used"),
                    "code_search_reset": reset_at,
                    "code_search_reset_bj": reset_at_bj,
                    "core_remaining": core.get("remaining"),
                    "health_score": entry.get("health_score", 100.0),
                    "success_count": entry.get("success_count", 0),
                    "failure_count": entry.get("failure_count", 0),
                    "rate_limit_count": entry.get("rate_limit_count", 0),
                    "disabled_until": disabled_until,
                    "disabled_until_bj": disabled_until_bj,
                    "last_error": entry.get("last_error") or "",
                    "last_checked": entry.get("last_checked"),
                    "last_success_at": entry.get("last_success_at"),
                    "ok": True,
                }
            )
        except Exception as exc:
            results.append(
                {
                    "token_index": index,
                    "ok": False,
                    "error": str(exc)[:120],
                    **entry,
                }
            )
    return results


def extract_runtime_snapshot(log_lines: list[str]) -> dict:
    joined = "\n".join(log_lines)
    ansi = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    clean = ansi.sub("", joined).replace("\r", "\n")
    fragments = [fragment.strip() for fragment in clean.split("\n") if fragment.strip()]

    startup_markers = [
        "异步验证器启动",
        "连接池已启动",
        "缓存管理器已启动",
        "性能监控已启动",
        "动态队列已启动",
        "GitHub Secret Scanner Pro v2.2",
    ]
    running = any(marker in clean for marker in startup_markers)

    snapshot = {
        "is_running": running,
        "status_text": "运行中" if running else "未知",
        "tokens_text": None,
        "proxy_text": "直连模式" if "直连模式" in clean else None,
        "current_search": None,
        "scanned_files": None,
        "found_keys": None,
        "valid_hits": None,
        "invalid_hits": None,
        "quota_hits": None,
        "connection_errors": None,
        "queue_size": None,
        "low_entropy_skipped": None,
        "blacklist_skipped": None,
        "skipped_sha": None,
        "skipped_file_filter": None,
        "recent_log_lines": fragments[-15:],
    }

    search_patterns = [
        r"搜索:\s*(.+)$",
        r"Request GET /search/code\?q=([^\s]+)",
    ]
    for pattern in search_patterns:
        match = re.search(pattern, clean, flags=re.MULTILINE)
        if match:
            snapshot["current_search"] = urllib.parse.unquote_plus(match.group(1).strip())
            break

    db_match = re.search(r"已扫描文件:\s*([\d,]+),\s*已入库 Key:\s*([\d,]+)", clean)
    if db_match:
        snapshot["scanned_files"] = db_match.group(1)
        snapshot["found_keys"] = db_match.group(2)

    return snapshot


def progress_line(channel: str, message: str, ts: str | None = None) -> str:
    """生成带渠道标识的扫描进展行。"""
    return f"[{ts or format_bj_now()}] [{channel}] {message}"


def infer_progress_channel(message: str) -> str:
    if "[Sourcegraph]" in message:
        return "Sourcegraph"
    if "Token" in message or "Code Search 配额" in message:
        return "Token"
    if "验证" in message or "VALID" in message or "HIGH" in message:
        return "验证"
    if "搜索" in message or "SCAN" in message:
        return "GitHub"
    if "Cache" in message:
        return "缓存"
    if "Monitor" in message:
        return "监控"
    return "系统"


def build_progress_lines(raw_lines: list[str], runtime_state: dict, quota_items: list[dict]) -> list[str]:
    progress = []
    stats = runtime_state.get("stats", {})
    updated_at = runtime_state.get("updated_at")
    if updated_at:
        try:
            progress.append(progress_line("系统", "状态已刷新", datetime.fromisoformat(updated_at).astimezone(CN_TZ).strftime('%Y-%m-%d %H:%M:%S')))
        except ValueError:
            progress.append(progress_line("系统", "状态已刷新"))

    scan_run_id = stats.get("scan_run_id")
    if scan_run_id:
        round_index = stats.get("round_keyword_index") or 0
        round_total = stats.get("round_total_keywords") or 0
        progress.append(progress_line("系统", f"当前轮次：{scan_run_id}，关键词进度 {round_index}/{round_total}"))

    if stats.get("is_running"):
        progress.append(progress_line("系统", f"扫描器运行中，当前队列 {stats.get('queue_size', 0)}"))

    keyword = stats.get("current_keyword")
    if keyword:
        progress.append(progress_line("GitHub", f"当前搜索：{keyword}"))

    scanned = stats.get("round_scanned", stats.get("total_scanned"))
    found = stats.get("round_keys_found", stats.get("total_keys_found"))
    if scanned is not None or found is not None:
        skipped_sha = stats.get("skipped_sha") or 0
        skipped_file_filter = stats.get("skipped_file_filter") or 0
        progress.append(progress_line(
            "统计",
            f"本轮新扫 {scanned or 0} 个文件，发现 {found or 0} 个 Key；"
            f"历史已扫跳过 {skipped_sha} 个，文件规则跳过 {skipped_file_filter} 个"
        ))

    valid = stats.get("round_valid_keys", stats.get("valid_keys"))
    quota_hits = stats.get("quota_exceeded")
    if valid is not None or quota_hits is not None:
        progress.append(progress_line("验证", f"已验证有效 {valid or 0} 个，配额耗尽 {quota_hits or 0} 个"))

    for item in quota_items:
        if not item.get("ok"):
            progress.append(progress_line("Token", f"Token {item.get('token_index')} 配额读取失败：{item.get('error', '未知错误')}"))
            continue
        remaining = item.get("code_search_remaining")
        limit = item.get("code_search_limit")
        reset_at = item.get("code_search_reset")
        reset_text = item.get("code_search_reset_bj") or '--'
        if reset_at and reset_text == '--':
            try:
                reset_text = datetime.fromisoformat(reset_at).astimezone(CN_TZ).strftime('%H:%M:%S')
            except ValueError:
                reset_text = reset_at
        if remaining == 0:
            progress.append(progress_line("Token", f"Token {item.get('token_index')} 的 Code Search 配额已用尽，预计北京时间 {reset_text} 恢复"))
        else:
            progress.append(progress_line("Token", f"Token {item.get('token_index')} 的 Code Search 配额剩余 {remaining}/{limit}，核心配额剩余 {item.get('core_remaining', '--')}"))

    rich_markup = re.compile(r"\[[^\]]+\]")
    for entry in runtime_state.get("recent_logs", [])[-12:]:
        clean_entry = rich_markup.sub("", entry).strip()
        if clean_entry:
            channel = infer_progress_channel(clean_entry)
            progress.append(progress_line(channel, f"最近事件：{clean_entry}"))

    # 原始 scanner.log 是追加式历史日志，混入旧启动/旧 403 会让面板看起来没更新。
    # 用户侧进展流只展示当前 runtime_state 与当前配额；原始日志留给容器日志排障。
    raw_lines = []

    seen = set()
    backoff_seen = False
    warning_seen = False
    for line in raw_lines[-120:]:
        line = line.strip()
        if not line:
            continue
        ts_match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) \| .* - (.*)$", line)
        if ts_match:
            ts_text, message = ts_match.groups()
            bj_time = format_bj_timestamp(ts_text)
            if "数据库初始化完成" in message and f"db:{message}" not in seen:
                progress.append(progress_line("系统", f"数据库已加载，{message.split(': ', 1)[-1]}", bj_time))
                seen.add(f"db:{message}")
            elif "配置验证通过" in message and "config_ok" not in seen:
                progress.append(progress_line("系统", "配置检查通过，扫描准备完成", bj_time))
                seen.add("config_ok")
            elif "连接池已启动" in message and "pool_ok" not in seen:
                progress.append(progress_line("系统", "网络连接池已启动", bj_time))
                seen.add("pool_ok")
            elif "异步验证器启动" in message and message not in seen:
                progress.append(progress_line("验证", f"验证线程已启动：{message.split('- ', 1)[-1]}", bj_time))
                seen.add(message)
            continue

        if "Request GET /search/code" in line and "failed with 403" in line:
            q_match = re.search(r"q=([^\s]+)", line)
            keyword = urllib.parse.unquote_plus(q_match.group(1)) if q_match else "当前关键词"
            key = f"quota403:{keyword}"
            if key not in seen:
                progress.append(progress_line("GitHub", f"Code Search 暂时卡住：{keyword}，原因是配额/风控限制"))
                seen.add(key)
        elif "Setting next backoff to" in line:
            backoff = re.search(r"Setting next backoff to ([\d.]+)s", line)
            if backoff and not backoff_seen:
                progress.append(progress_line("系统", f"已自动退避，约 {round(float(backoff.group(1)))} 秒后重试"))
                backoff_seen = True
        elif "RuntimeWarning" in line:
            if not warning_seen:
                progress.append(progress_line("系统", "扫描器出现内部告警，需要后续修一下异步队列调用"))
                warning_seen = True

    compact = []
    seen_text = set()
    for line in progress:
        if line not in seen_text:
            compact.append(line)
            seen_text.add(line)
    return compact[-40:]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_FILE.read_text(encoding="utf-8")


@app.post("/api/login")
def login(payload: dict, response: Response) -> dict:
    username = (payload or {}).get("username", "")
    password = (payload or {}).get("password", "")
    if username != PANEL_USERNAME or password != PANEL_PASSWORD:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")

    token = secrets.token_urlsafe(32)
    PANEL_SESSIONS[token] = username
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=86400,
    )
    return {"ok": True, "username": username}


@app.post("/api/logout")
def logout(request: Request, response: Response) -> dict:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        PANEL_SESSIONS.pop(token, None)
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/me")
def me(user: str = Depends(get_current_user)) -> dict:
    return {"ok": True, "username": user}


@app.get("/api/health")
def health() -> dict:
    with get_conn() as conn:
        conn.execute("SELECT 1")
    return {"ok": True}


@app.get("/api/stats")
def stats(user: str = Depends(get_current_user)) -> dict:
    runtime_state = read_runtime_state()
    runtime_stats = runtime_state.get("stats", {})
    log_lines = read_log_lines(200)
    runtime = extract_runtime_snapshot(log_lines)

    runtime["is_running"] = runtime_stats.get("is_running", runtime.get("is_running"))
    runtime["status_text"] = "运行中" if runtime["is_running"] else runtime.get("status_text", "未知")
    runtime["current_search"] = runtime_stats.get("current_keyword") or runtime.get("current_search")
    runtime["scanned_files"] = runtime_stats.get("total_scanned", runtime.get("scanned_files"))
    runtime["found_keys"] = runtime_stats.get("total_keys_found", runtime.get("found_keys"))
    runtime["valid_hits"] = runtime_stats.get("valid_keys", runtime.get("valid_hits"))
    runtime["invalid_hits"] = runtime_stats.get("invalid_keys", runtime.get("invalid_hits"))
    runtime["quota_hits"] = runtime_stats.get("quota_exceeded", runtime.get("quota_hits"))
    runtime["connection_errors"] = runtime_stats.get("connection_errors", runtime.get("connection_errors"))
    runtime["error_keys"] = runtime_stats.get("error_keys", runtime.get("error_keys", 0))
    runtime["unverified_keys"] = runtime_stats.get("unverified_keys", runtime.get("unverified_keys", 0))
    runtime["skipped_existing"] = runtime_stats.get("skipped_existing", runtime.get("skipped_existing", 0))
    runtime["queue_size"] = runtime_stats.get("queue_size", runtime.get("queue_size"))
    runtime["low_entropy_skipped"] = runtime_stats.get("skipped_low_entropy", runtime.get("low_entropy_skipped"))
    runtime["blacklist_skipped"] = runtime_stats.get("skipped_blacklist", runtime.get("blacklist_skipped"))
    runtime["skipped_sha"] = runtime_stats.get("skipped_sha", runtime.get("skipped_sha"))
    runtime["skipped_file_filter"] = runtime_stats.get("skipped_file_filter", runtime.get("skipped_file_filter"))
    runtime["tokens_text"] = (
        f"{runtime_stats.get('current_token_index', 0) + 1}/{runtime_stats.get('total_tokens', 0)}"
        if runtime_stats.get("total_tokens")
        else None
    )
    runtime["recent_log_lines"] = runtime_state.get("recent_logs", runtime.get("recent_log_lines", []))
    runtime["scan_run_id"] = runtime_stats.get("scan_run_id")
    runtime["round_number"] = runtime_stats.get("round_number")
    runtime["round_keyword_index"] = runtime_stats.get("round_keyword_index")
    runtime["round_total_keywords"] = runtime_stats.get("round_total_keywords")
    runtime["round_scanned"] = runtime_stats.get("round_scanned")
    runtime["round_keys_found"] = runtime_stats.get("round_keys_found")
    runtime["round_valid_keys"] = runtime_stats.get("round_valid_keys")
    runtime["round_started_at"] = runtime_stats.get("round_started_at")
    runtime["keys_by_source"] = runtime_stats.get("keys_by_source", {})
    runtime["query_quality"] = runtime_stats.get("query_quality", {})

    try:
        with get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM leaked_keys").fetchone()[0]
            scanned_blobs = conn.execute("SELECT COUNT(*) FROM scanned_blobs").fetchone()[0]
            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS count FROM leaked_keys GROUP BY status ORDER BY count DESC"
            ).fetchall()
            platform_rows = conn.execute(
                "SELECT platform, COUNT(*) AS count FROM leaked_keys GROUP BY platform ORDER BY count DESC LIMIT 10"
            ).fetchall()
            high_value = conn.execute(
                "SELECT COUNT(*) FROM leaked_keys WHERE is_high_value = 1"
            ).fetchone()[0]
            recent = conn.execute(
                "SELECT COUNT(*) FROM leaked_keys WHERE found_time >= datetime('now', '-24 hours')"
            ).fetchone()[0]
            daily_rows = conn.execute(
                """
                SELECT substr(found_time, 1, 10) AS day, COUNT(*) AS count
                FROM leaked_keys
                WHERE found_time IS NOT NULL
                GROUP BY day
                ORDER BY day DESC
                LIMIT 14
                """
            ).fetchall()
        db_ok = True
    except sqlite3.OperationalError:
        total = 0
        scanned_blobs = 0
        status_rows = []
        platform_rows = []
        high_value = 0
        recent = 0
        daily_rows = []
        db_ok = False

    statuses = {row["status"]: row["count"] for row in status_rows}
    platforms = [{"platform": row["platform"], "count": row["count"]} for row in platform_rows]
    valid_total = int(runtime.get("valid_hits") or statuses.get("valid", 0)) + int(runtime.get("quota_hits") or statuses.get("quota_exceeded", 0))
    invalid_total = int(runtime.get("invalid_hits") or statuses.get("invalid", 0))
    quota_total = int(runtime.get("quota_hits") or statuses.get("quota_exceeded", 0))
    connection_total = int(runtime.get("connection_errors") or statuses.get("connection_error", 0))
    error_total = int(runtime.get("error_keys") or 0)
    unverified_stat_total = int(runtime.get("unverified_keys") or 0)
    skipped_existing_total = int(runtime.get("skipped_existing") or 0)
    verified_total = valid_total + invalid_total + connection_total + error_total + unverified_stat_total + skipped_existing_total
    discovered_total = int(runtime.get("found_keys") or total or 0)
    unverified_total = max(discovered_total - verified_total, 0)
    daily = list(reversed([{"day": row["day"], "count": row["count"]} for row in daily_rows]))

    return {
        "total": total,
        "valid_total": valid_total,
        "verified_total": verified_total,
        "unverified_total": unverified_total,
        "error_total": error_total,
        "unverified_stat_total": unverified_stat_total,
        "high_value": high_value,
        "recent_24h": recent,
        "scanned_blobs": scanned_blobs,
        "statuses": statuses,
        "platforms": platforms,
        "daily": daily,
        "db_ok": db_ok,
        "keys_by_source": runtime.get("keys_by_source", {}),
        "runtime": runtime,
        "runtime_state_updated_at": runtime_state.get("updated_at"),
        "recent_valid_keys": runtime_state.get("valid_keys", []),
        "github_quota": get_github_quota(),
        "proxy_pool": get_proxy_pool_stats(),
    }



@app.get("/api/config")
def get_config(user: str = Depends(get_current_user)) -> dict:
    tokens = [t[:8] + "..." if len(t) > 8 else t for t in scanner_config.github_tokens if t]
    return {
        "proxy_url": scanner_config.proxy_url or "",
        "proxy_urls": list(scanner_config.proxy_urls) if hasattr(scanner_config, "proxy_urls") else [],
        "github_tokens_count": len([t for t in scanner_config.github_tokens if t]),
        "github_tokens_masked": tokens,
        "enabled_providers": list(scanner_config.enabled_providers) if hasattr(scanner_config, "enabled_providers") else [],
        "db_path": scanner_config.db_path,
        "consumer_threads": getattr(scanner_config, "consumer_threads", 20),
        "request_timeout": getattr(scanner_config, "request_timeout", 15),
        "circuit_breaker_enabled": getattr(scanner_config, "circuit_breaker_enabled", True),
        "context_window": getattr(scanner_config, "context_window", 10),
        "search_keywords": list(scanner_config.search_keywords) if hasattr(scanner_config, "search_keywords") and scanner_config.search_keywords else [],
        "max_concurrency": 100,
        "pastebin_api_key_masked": (scanner_config.pastebin_api_key[:8] + "...") if hasattr(scanner_config, "pastebin_api_key") and len(scanner_config.pastebin_api_key) > 8 else "",
        "redis_url": getattr(scanner_config, "redis_url", ""),
        "env_github_tokens": bool(os.getenv("GITHUB_TOKENS")),
        "env_proxy_url": os.getenv("PROXY_URL", ""),
        "env_enabled_providers": os.getenv("ENABLED_PROVIDERS", ""),
    }


@app.post("/api/config/update")
def update_config(payload: dict, user: str = Depends(get_current_user)) -> dict:
    allowed_keys = {
        "proxy_url", "consumer_threads", "request_timeout",
        "context_window", "max_concurrency", "circuit_breaker_enabled",
        "pastebin_api_key", "redis_url",
    }
    lines = []
    lines.append("# Auto-generated by Scanner Panel")
    lines.append("")

    tokens = os.getenv("GITHUB_TOKENS", "")
    if tokens:
        token_list = ['    "' + t.strip() + '",' for t in tokens.split(",") if t.strip()]
        lines.append("GITHUB_TOKENS = [")
        lines.extend(token_list)
        lines.append("]")
        lines.append("")

    proxy = payload.get("proxy_url") or os.getenv("PROXY_URL", "")
    if proxy:
        lines.append('PROXY_URL = "' + proxy + '"')
        lines.append("")

    providers = payload.get("enabled_providers", [])
    if providers:
        provs = ", ".join('"' + p.strip() + '"' for p in providers if p.strip())
        lines.append("ENABLED_PROVIDERS = [" + provs + "]")
        lines.append("")

    keywords = payload.get("search_keywords", [])
    if keywords:
        kws = ", ".join('"' + k.strip() + '"' for k in keywords if k.strip())
        lines.append("SEARCH_KEYWORDS = [" + kws + "]")
        lines.append("")

    for key in allowed_keys:
        if key in payload:
            val = payload[key]
            if isinstance(val, str):
                lines.append(key.upper() + ' = "' + val + '"')
            elif isinstance(val, bool):
                lines.append(key.upper() + " = " + ("True" if val else "False"))
            elif isinstance(val, int):
                lines.append(key.upper() + " = " + str(val))
            elif isinstance(val, float):
                lines.append(key.upper() + " = " + str(val))
    lines.append("")

    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"ok": True, "message": "配置已写入 " + str(CONFIG_PATH)}
    except Exception as exc:
        return {"ok": False, "message": "写入失败: " + str(exc)}
@app.get("/api/keys")
def keys(
    status: Optional[str] = Query(default=None),
    platform: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    user: str = Depends(get_current_user),
) -> dict:
    where = []
    params = []

    if status:
        where.append("status = ?")
        params.append(status)
    if platform:
        where.append("platform = ?")
        params.append(platform)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    offset = (page - 1) * page_size

    try:
        with get_conn() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM leaked_keys {where_sql}", params).fetchone()[0]
            rows = conn.execute(
                f"""
                SELECT id, platform, api_key, base_url, status, balance, source_url,
                       model_tier, rpm, is_high_value, found_time, verified_time
                FROM leaked_keys
                {where_sql}
                ORDER BY datetime(found_time) DESC
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, offset],
            ).fetchall()
    except sqlite3.OperationalError:
        total = 0
        rows = []

    items = [
        {
            "id": row["id"],
            "platform": row["platform"],
            "api_key_masked": mask_key(row["api_key"] or ""),
            "base_url": row["base_url"],
            "status": row["status"],
            "balance": row["balance"],
            "source_url": row["source_url"],
            "model_tier": row["model_tier"],
            "rpm": row["rpm"],
            "is_high_value": bool(row["is_high_value"]),
            "found_time": row["found_time"],
            "verified_time": row["verified_time"],
        }
        for row in rows
    ]

    return {
        "total": total,
        "items": items,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@app.get("/api/recent")
def recent(limit: int = Query(default=20, ge=1, le=100), user: str = Depends(get_current_user)) -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT platform, status, model_tier, is_high_value, found_time, balance, source_url
            FROM leaked_keys
            ORDER BY datetime(found_time) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return {"items": [dict(row) for row in rows]}


@app.get("/api/logs")
def logs(lines: int = Query(default=100, ge=10, le=500), user: str = Depends(get_current_user)) -> dict:
    raw_lines = read_log_lines(max(lines, 200))
    runtime_state = read_runtime_state()
    quota_items = get_github_quota()
    progress_lines = build_progress_lines(raw_lines, runtime_state, quota_items)
    return {"lines": progress_lines[-lines:]}


@app.get("/api/logs/stream")
def logs_stream(user: str = Depends(get_current_user)) -> StreamingResponse:
    def generate():
        last_line = None
        while True:
            raw_lines = read_log_lines(200)
            runtime_state = read_runtime_state()
            quota_items = get_github_quota()
            progress_lines = build_progress_lines(raw_lines, runtime_state, quota_items)
            if progress_lines:
                newest = progress_lines[-1]
                if newest != last_line:
                    last_line = newest
                    yield f"data: {json.dumps({'line': newest}, ensure_ascii=False)}\n\n"
            time.sleep(5)

    return StreamingResponse(generate(), media_type="text/event-stream")
