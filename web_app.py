import json
import os
import re
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
import runpy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from proxy_pool import get_proxy_pool, init_proxy_pool
import asyncio
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


def normalize_display_text(text: str) -> str:
    if not text:
        return ""
    if any(token in text for token in ["鎼", "鍙", "绛", "閰", "鏃", "鍏", "鐨", "璇"]):
        try:
            repaired = text.encode("latin1", errors="ignore").decode("utf-8", errors="ignore")
            if repaired:
                return repaired
        except Exception:
            return text
    return text

def read_log_lines(limit: int = 200) -> list[str]:
    if not SCANNER_LOG_PATH.exists() or not SCANNER_LOG_PATH.is_file():
        return []
    with SCANNER_LOG_PATH.open("r", encoding="utf-8", errors="replace") as handle:
        raw_lines = handle.readlines()

    parsed = []
    for line in raw_lines:
        text = normalize_display_text(line.rstrip("\n"))
        try:
            payload = json.loads(text)
            parsed.append(payload.get("log", text))
        except json.JSONDecodeError:
            parsed.append(text)

    run_markers = (
        "SCAN_RUN_START",
        "Scan run started:",
        "GitHub Secret Scanner Pro",
        "Gist scanner started",
        "GitLab scanner started",
        "Sourcegraph fallback scanner started",
    )
    start_index = 0
    for index in range(len(parsed) - 1, -1, -1):
        entry = parsed[index]
        if any(marker in entry for marker in run_markers):
            start_index = index
            break

    current_window = parsed[start_index:]
    return current_window[-limit:]


def read_runtime_state() -> dict:
    if not RUNTIME_STATE_PATH.exists() or not RUNTIME_STATE_PATH.is_file():
        return {}
    try:
        return json.loads(RUNTIME_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}





def runtime_legacy_stats(runtime_state: dict) -> dict:
    return runtime_state.get("stats", {}) or {}


def runtime_current_run(runtime_state: dict) -> dict:
    legacy = runtime_legacy_stats(runtime_state)
    current = runtime_state.get("current_run", {}) or {}
    return {
        "is_running": current.get("is_running", legacy.get("is_running", False)),
        "scan_run_id": current.get("scan_run_id") or legacy.get("scan_run_id") or "",
        "round_number": int(current.get("round_number", legacy.get("round_number", 0)) or 0),
        "round_keyword_index": int(current.get("round_keyword_index", legacy.get("round_keyword_index", 0)) or 0),
        "round_total_keywords": int(current.get("round_total_keywords", legacy.get("round_total_keywords", 0)) or 0),
        "round_scanned": int(current.get("round_scanned", legacy.get("round_scanned", 0)) or 0),
        "round_keys_found": int(current.get("round_keys_found", legacy.get("round_keys_found", 0)) or 0),
        "round_valid_keys": int(current.get("round_valid_keys", legacy.get("round_valid_keys", 0)) or 0),
        "round_started_at": current.get("round_started_at") or legacy.get("round_started_at") or "",
        "current_keyword": current.get("current_keyword") or legacy.get("current_keyword") or "",
        "current_source": current.get("current_source") or legacy.get("current_source") or "",
        "current_target": current.get("current_target") or legacy.get("current_target") or "",
        "current_source_type": current.get("current_source_type") or legacy.get("current_source_type") or "",
        "current_source_score": float(current.get("current_source_score", legacy.get("current_source_score", 0.0)) or 0.0),
        "current_token_index": int(current.get("current_token_index", legacy.get("current_token_index", 0)) or 0),
        "total_tokens": int(current.get("total_tokens", legacy.get("total_tokens", 0)) or 0),
        "queue_size": int(current.get("queue_size", legacy.get("queue_size", 0)) or 0),
        "search_budget_total": int(current.get("search_budget_total", legacy.get("search_budget_total", 0)) or 0),
        "search_budget_used": int(current.get("search_budget_used", legacy.get("search_budget_used", 0)) or 0),
    }


def runtime_counters(runtime_state: dict) -> dict:
    legacy = runtime_legacy_stats(runtime_state)
    counters = runtime_state.get("counters", {}) or {}
    return {
        "total_scanned": int(counters.get("total_scanned", legacy.get("total_scanned", 0)) or 0),
        "total_keys_found": int(counters.get("total_keys_found", legacy.get("total_keys_found", 0)) or 0),
        "candidates_discovered": int(counters.get("candidates_discovered", legacy.get("candidates_discovered", 0)) or 0),
        "repos_enqueued": int(counters.get("repos_enqueued", legacy.get("repos_enqueued", 0)) or 0),
        "repos_scanned": int(counters.get("repos_scanned", legacy.get("repos_scanned", 0)) or 0),
        "valid_total": int(counters.get("valid_keys", legacy.get("valid_keys", 0)) or 0),
        "invalid_total": int(counters.get("invalid_keys", legacy.get("invalid_keys", 0)) or 0),
        "quota_exceeded_total": int(counters.get("quota_exceeded_total", legacy.get("quota_exceeded", 0)) or 0),
        "connection_error_total": int(counters.get("connection_errors", legacy.get("connection_errors", 0)) or 0),
        "error_total": int(counters.get("error_total", legacy.get("error_keys", 0)) or 0),
        "unverified_total": int(counters.get("unverified_total", legacy.get("unverified_keys", 0)) or 0),
        "skipped_low_entropy": int(counters.get("skipped_low_entropy", legacy.get("skipped_low_entropy", 0)) or 0),
        "skipped_blacklist": int(counters.get("skipped_blacklist", legacy.get("skipped_blacklist", 0)) or 0),
        "skipped_sha": int(counters.get("skipped_sha", legacy.get("skipped_sha", 0)) or 0),
        "skipped_file_filter": int(counters.get("skipped_file_filter", legacy.get("skipped_file_filter", 0)) or 0),
        "skipped_existing": int(counters.get("skipped_existing", legacy.get("skipped_existing", 0)) or 0),
    }


def runtime_quality(runtime_state: dict) -> dict:
    legacy = runtime_legacy_stats(runtime_state)
    quality = runtime_state.get("quality", {}) or {}
    return {
        "keys_by_source": quality.get("keys_by_source", legacy.get("keys_by_source", {})) or {},
        "source_breakdown": quality.get("source_breakdown", legacy.get("source_breakdown", {})) or {},
        "query_quality": quality.get("query_quality", legacy.get("query_quality", {})) or {},
    }


def normalize_status_label(status_value: str) -> str:
    status_value = (status_value or "").strip().lower()
    mapping = {
        "valid": "valid",
        "invalid": "invalid",
        "quota_exceeded": "quota_exceeded",
        "connection_error": "connection_error",
        "pending": "pending",
        "unverified": "unverified",
    }
    return mapping.get(status_value, status_value or "unknown")


def normalize_balance_text(balance_value: str) -> str:
    text = normalize_display_text(balance_value or "").strip()
    lowered = text.lower()
    if not text:
        return ""
    if "连接失败" in text or "connection error" in lowered or "connection failed" in lowered:
        return "Connection failed"
    if "配额耗尽" in text or "quota exceeded" in lowered or "credit balance is too low" in lowered:
        return "Quota exceeded"
    if "有效(chat)" in text:
        return text.replace("有效(chat)", "Valid (chat)")
    if text == "有效":
        return "Valid"
    if text == "无效":
        return "Invalid"
    return text


def normalize_model_tier(value: str) -> str:
    return normalize_display_text(value or "").strip()


def normalize_result_row(row: dict) -> dict:
    normalized = dict(row)
    normalized["status"] = normalize_status_label(normalized.get("status", ""))
    normalized["balance"] = normalize_balance_text(normalized.get("balance", ""))
    normalized["model_tier"] = normalize_model_tier(normalized.get("model_tier", ""))
    normalized["platform"] = (normalized.get("platform") or "").strip().lower()
    normalized["source_url"] = normalize_display_text(normalized.get("source_url", "") or "")
    return normalized


def normalize_progress_feed(progress_lines: list[str]) -> list[dict]:
    feed = []
    pattern = re.compile(r"^\[(?P<ts>[^\]]+)\] \[(?P<channel>[^\]]+)\] (?P<message>.*)$")
    for line in progress_lines:
        match = pattern.match(line)
        if match:
            feed.append({
                "timestamp": match.group("ts"),
                "channel": match.group("channel"),
                "message": match.group("message"),
                "line": line,
            })
        else:
            feed.append({"timestamp": "", "channel": "系统", "message": line, "line": line})
    return feed


def read_persisted_config() -> dict:
    if not CONFIG_PATH.exists() or not CONFIG_PATH.is_file():
        return {}
    try:
        namespace = runpy.run_path(str(CONFIG_PATH))
    except Exception:
        return {}
    return {
        "proxy_url": namespace.get("PROXY_URL", ""),
        "dynamic_proxy_source_url": namespace.get("DYNAMIC_PROXY_SOURCE_URL", ""),
        "enabled_providers": list(namespace.get("ENABLED_PROVIDERS", []) or []),
        "search_keywords": list(namespace.get("SEARCH_KEYWORDS", []) or []),
        "consumer_threads": namespace.get("CONSUMER_THREADS"),
        "request_timeout": namespace.get("REQUEST_TIMEOUT"),
        "context_window": namespace.get("CONTEXT_WINDOW"),
        "max_concurrency": namespace.get("MAX_CONCURRENCY"),
        "redis_url": namespace.get("REDIS_URL", ""),
        "circuit_breaker_enabled": namespace.get("CIRCUIT_BREAKER_ENABLED"),
    }
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
    log_lines = [normalize_display_text(line) for line in log_lines]
    joined = "\n".join(log_lines)
    ansi = re.compile(r"\[[0-9;]*[A-Za-z]")
    clean = ansi.sub("", joined).replace("\r", "\n")
    fragments = [fragment.strip() for fragment in clean.split("\n") if fragment.strip()]

    startup_markers = [
        "异步验证器启动",
        "连接池已启动",
        "缓存管理器已启动",
        "性能监控已启动",
        "动态队列已启动",
        "GitHub Secret Scanner Pro",
        "async validator started",
        "connection pool started",
        "cache manager started",
        "performance monitor started",
        "dynamic queue started",
    ]
    running = any(marker in clean for marker in startup_markers)

    proxy_clean = clean.lower()
    snapshot = {
        "is_running": running,
        "status_text": "Running" if running else "Unknown",
        "tokens_text": None,
        "proxy_text": "Direct mode" if ("直连模式" in clean or "direct mode" in proxy_clean) else None,
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
        r"Search:\s*(.+)$",
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
    """Generate a structured progress line for the dashboard."""
    return f"[{ts or format_bj_now()}] [{channel}] {message}"


def infer_progress_channel(message: str) -> str:
    message = normalize_display_text(message)
    lowered = message.lower()
    if "[sourcegraph]" in lowered:
        return "Sourcegraph"
    if "token" in lowered or "code search 配额" in message or "code search quota" in lowered:
        return "Token"
    if "验证" in message or "valid" in lowered or "high" in lowered or "validator" in lowered or "validation" in lowered:
        return "Validation"
    if "搜索" in message or "scan" in lowered or "search:" in lowered or "searching" in lowered:
        return "GitHub"
    if "cache" in lowered:
        return "Cache"
    if "monitor" in lowered:
        return "Monitor"
    return "System"


def build_progress_lines(raw_lines: list[str], runtime_state: dict, quota_items: list[dict]) -> list[str]:
    progress = []
    stats = runtime_state.get("stats", {})
    updated_at = runtime_state.get("updated_at")
    if updated_at:
        try:
            progress.append(progress_line("System", "Runtime state refreshed", datetime.fromisoformat(updated_at).astimezone(CN_TZ).strftime('%Y-%m-%d %H:%M:%S')))
        except ValueError:
            progress.append(progress_line("System", "Runtime state refreshed"))

    scan_run_id = stats.get("scan_run_id")
    if scan_run_id:
        round_index = stats.get("round_keyword_index") or 0
        round_total = stats.get("round_total_keywords") or 0
        progress.append(progress_line("System", f"Current run {scan_run_id}, keyword progress {round_index}/{round_total}"))

    if stats.get("is_running"):
        progress.append(progress_line("System", f"Scanner running, queue size {stats.get('queue_size', 0)}"))

    keyword = stats.get("current_keyword")
    if keyword:
        progress.append(progress_line("GitHub", f"Current search: {keyword}"))

    scanned = stats.get("round_scanned", stats.get("total_scanned"))
    found = stats.get("round_keys_found", stats.get("total_keys_found"))
    if scanned is not None or found is not None:
        skipped_sha = stats.get("skipped_sha") or 0
        skipped_file_filter = stats.get("skipped_file_filter") or 0
        progress.append(progress_line(
            "Stats",
            f"Scanned {scanned or 0} files this run and found {found or 0} keys; "
            f"skipped by SHA {skipped_sha}, skipped by file rules {skipped_file_filter}"
        ))

    valid = stats.get("round_valid_keys", stats.get("valid_keys"))
    quota_hits = stats.get("quota_exceeded")
    if valid is not None or quota_hits is not None:
        progress.append(progress_line("Validation", f"Verified valid {valid or 0}, quota exceeded {quota_hits or 0}"))

    for item in quota_items:
        if not item.get("ok"):
            progress.append(progress_line("Token", f"Token {item.get('token_index')} quota read failed: {item.get('error', 'unknown error')}"))
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
            progress.append(progress_line("Token", f"Token {item.get('token_index')} Code Search quota exhausted, resets around {reset_text} BJ time"))
        else:
            progress.append(progress_line("Token", f"Token {item.get('token_index')} Code Search remaining {remaining}/{limit}, core remaining {item.get('core_remaining', '--')}"))

    rich_markup = re.compile(r"\[[^\]]+\]")
    for entry in runtime_state.get("recent_logs", [])[-12:]:
        clean_entry = rich_markup.sub("", entry).strip()
        if clean_entry:
            channel = infer_progress_channel(clean_entry)
            progress.append(progress_line(channel, f"Recent event: {clean_entry}"))

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
            lowered = message.lower()
            if ("数据库初始化完成" in message or "database loaded" in lowered) and f"db:{message}" not in seen:
                progress.append(progress_line("System", f"Database loaded: {message.split(': ', 1)[-1]}", bj_time))
                seen.add(f"db:{message}")
            elif ("配置验证通过" in message or "configuration verified" in lowered) and "config_ok" not in seen:
                progress.append(progress_line("System", "Configuration verified, scanner ready", bj_time))
                seen.add("config_ok")
            elif ("连接池已启动" in message or "connection pool started" in lowered) and "pool_ok" not in seen:
                progress.append(progress_line("System", "Connection pool started", bj_time))
                seen.add("pool_ok")
            elif ("异步验证器启动" in message or "validator started" in lowered) and message not in seen:
                detail = message.split('- ', 1)[-1] if '- ' in message else message
                progress.append(progress_line("Validation", f"Validator started: {detail}", bj_time))
                seen.add(message)
            continue

        if "Request GET /search/code" in line and "failed with 403" in line:
            q_match = re.search(r"q=([^\s]+)", line)
            keyword = urllib.parse.unquote_plus(q_match.group(1)) if q_match else "current keyword"
            key = f"quota403:{keyword}"
            if key not in seen:
                progress.append(progress_line("GitHub", f"Code Search paused for {keyword} due to quota or abuse limits"))
                seen.add(key)
        elif "Setting next backoff to" in line:
            backoff = re.search(r"Setting next backoff to ([\d.]+)s", line)
            if backoff and not backoff_seen:
                progress.append(progress_line("System", f"Automatic backoff active, retrying in about {round(float(backoff.group(1)))}s"))
                backoff_seen = True
        elif "RuntimeWarning" in line:
            if not warning_seen:
                progress.append(progress_line("System", "Scanner emitted an internal warning; async queue handling needs follow-up"))
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
    current_run = runtime_current_run(runtime_state)
    counters = runtime_counters(runtime_state)
    quality = runtime_quality(runtime_state)
    raw_lines = read_log_lines(200)
    quota_items = get_github_quota()
    progress_lines = build_progress_lines(raw_lines, runtime_state, quota_items)

    runtime_snapshot = extract_runtime_snapshot(raw_lines)
    if not current_run.get("current_keyword") and runtime_snapshot.get("current_search"):
        current_run["current_keyword"] = runtime_snapshot.get("current_search")
    if not current_run.get("is_running") and runtime_snapshot.get("is_running"):
        current_run["is_running"] = True

    try:
        with get_conn() as conn:
            total_rows = conn.execute("SELECT COUNT(*) FROM leaked_keys").fetchone()[0]
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
            recent_rows = conn.execute(
                """
                SELECT platform, status, model_tier, is_high_value, found_time, balance, source_url
                FROM leaked_keys
                ORDER BY datetime(found_time) DESC
                LIMIT 12
                """
            ).fetchall()
        db_ok = True
    except sqlite3.OperationalError:
        total_rows = 0
        scanned_blobs = 0
        status_rows = []
        platform_rows = []
        high_value = 0
        recent_rows = []
        db_ok = False

    statuses = {row["status"]: int(row["count"]) for row in status_rows}
    platform_breakdown = {row["platform"]: int(row["count"]) for row in platform_rows if row["platform"]}
    status_breakdown = {
        "valid": statuses.get("valid", 0),
        "quota_exceeded": statuses.get("quota_exceeded", 0),
        "invalid": statuses.get("invalid", 0),
        "connection_error": statuses.get("connection_error", 0),
        "pending": statuses.get("pending", 0),
        "unverified": statuses.get("unverified", 0),
    }

    source_breakdown = quality.get("source_breakdown", {})
    query_quality_raw = quality.get("query_quality", {})
    query_quality = []
    for keyword, metrics in sorted(
        query_quality_raw.items(),
        key=lambda item: (item[1].get("score", 0), item[1].get("valid", 0), item[1].get("found", 0)),
        reverse=True,
    )[:10]:
        scanned = int(metrics.get("scanned", 0) or 0)
        found = int(metrics.get("found", 0) or 0)
        valid = int(metrics.get("valid", 0) or 0)
        query_quality.append({
            "keyword": keyword,
            "scanned": scanned,
            "found": found,
            "valid": valid,
            "score": float(metrics.get("score", 0.0) or 0.0),
            "yield_per_query": round(found / scanned, 4) if scanned else 0.0,
            "valid_rate": round(valid / found, 4) if found else 0.0,
            "last_seen": metrics.get("last_seen") or "",
        })

    source_view = []
    for source_name, metrics in sorted(
        source_breakdown.items(),
        key=lambda item: (item[1].get("keys_valid", 0), item[1].get("keys_found", 0), item[1].get("repos_scanned", 0)),
        reverse=True,
    ):
        files_scanned = int(metrics.get("files_scanned", 0) or 0)
        keys_found = int(metrics.get("keys_found", 0) or 0)
        keys_valid = int(metrics.get("keys_valid", 0) or 0)
        source_view.append({
            "source": source_name,
            "candidates_discovered": int(metrics.get("candidates_discovered", 0) or 0),
            "repos_enqueued": int(metrics.get("repos_enqueued", 0) or 0),
            "repos_scanned": int(metrics.get("repos_scanned", 0) or 0),
            "files_scanned": files_scanned,
            "keys_found": keys_found,
            "keys_valid": keys_valid,
            "hit_rate": round(keys_found / files_scanned, 4) if files_scanned else 0.0,
            "valid_rate": round(keys_valid / keys_found, 4) if keys_found else 0.0,
            "skipped": metrics.get("skipped", {}) or {},
            "last_seen": metrics.get("last_seen") or "",
        })

    quota_summary = {
        "total_tokens": len(quota_items),
        "healthy_tokens": len([item for item in quota_items if item.get("ok")]),
        "exhausted_tokens": len([item for item in quota_items if item.get("ok") and item.get("code_search_remaining") == 0]),
        "items": quota_items,
    }

    overview = {
        "discovered_total": counters["total_keys_found"] or total_rows,
        "valid_total": counters["valid_total"],
        "invalid_total": counters["invalid_total"],
        "quota_exceeded_total": counters["quota_exceeded_total"],
        "unverified_total": counters["unverified_total"],
        "error_total": counters["error_total"] + counters["connection_error_total"],
        "scanned_files": counters["total_scanned"],
        "candidates_discovered": counters["candidates_discovered"],
        "repos_enqueued": counters["repos_enqueued"],
        "repos_scanned": counters["repos_scanned"],
        "high_value_total": high_value,
        "scanned_blobs": scanned_blobs,
        "db_total": total_rows,
        "db_ok": db_ok,
    }

    run_status = {
        **current_run,
        "status_text": "Running" if current_run.get("is_running") else "Idle",
        "tokens_text": (
            f"{current_run.get('current_token_index', 0) + 1}/{current_run.get('total_tokens', 0)}"
            if current_run.get("total_tokens")
            else "--"
        ),
    }

    recent_valid_keys = runtime_state.get("valid_keys", [])
    recent_results = [normalize_result_row(dict(row)) for row in recent_rows]

    return {
        "overview": overview,
        "run_status": run_status,
        "quota": quota_summary,
        "source_breakdown": source_view,
        "platform_breakdown": platform_breakdown,
        "status_breakdown": status_breakdown,
        "query_quality": query_quality,
        "recent_valid_keys": recent_valid_keys,
        "recent_results": recent_results,
        "progress_feed": normalize_progress_feed(progress_lines),
        "raw_log_lines": raw_lines[-80:],
        "runtime_state_updated_at": runtime_state.get("updated_at"),
        "proxy_pool": runtime_state.get("proxy_pool") or get_proxy_pool_stats(),
        "keys_by_source": quality.get("keys_by_source", {}),
        "legacy": {
            "total": total_rows,
            "valid_total": overview["valid_total"],
            "platforms": platform_breakdown,
        },
    }


@app.get("/api/config")
def get_config(user: str = Depends(get_current_user)) -> dict:
    tokens = [t[:8] + "..." if len(t) > 8 else t for t in scanner_config.github_tokens if t]
    persisted = read_persisted_config()
    effective = {
        "proxy_url": scanner_config.proxy_url or "",
        "proxy_urls": list(scanner_config.proxy_urls) if hasattr(scanner_config, "proxy_urls") else [],
        "dynamic_proxy_source_url": getattr(scanner_config, "dynamic_proxy_source_url", "") or "",
        "enabled_providers": list(scanner_config.enabled_providers) if hasattr(scanner_config, "enabled_providers") else [],
        "search_keywords": list(scanner_config.search_keywords) if getattr(scanner_config, "search_keywords", None) else list(scanner_config.get_scheduled_search_keywords()[:12]),
        "db_path": scanner_config.db_path,
        "consumer_threads": getattr(scanner_config, "consumer_threads", 20),
        "request_timeout": getattr(scanner_config, "request_timeout", 15),
        "circuit_breaker_enabled": getattr(scanner_config, "circuit_breaker_enabled", True),
        "context_window": getattr(scanner_config, "context_window", 10),
        "max_concurrency": int(os.getenv("MAX_CONCURRENCY", "100") or 100),
        "redis_url": getattr(scanner_config, "redis_url", ""),
    }
    env_view = {
        "github_tokens_present": bool(os.getenv("GITHUB_TOKENS")),
        "github_tokens_count": len([t for t in os.getenv("GITHUB_TOKENS", "").split(",") if t.strip()]),
        "github_tokens_masked": tokens,
        "proxy_url": os.getenv("PROXY_URL", ""),
        "dynamic_proxy_source_url": os.getenv("DYNAMIC_PROXY_SOURCE_URL", ""),
        "enabled_providers": os.getenv("ENABLED_PROVIDERS", ""),
        "redis_url": os.getenv("REDIS_URL", ""),
        "code_search_keyword_budget": os.getenv("CODE_SEARCH_KEYWORD_BUDGET", "8"),
        "git_clone_code_search_budget": os.getenv("GIT_CLONE_CODE_SEARCH_BUDGET", "4"),
    }
    return {
        "effective": effective,
        "env": env_view,
        "persisted": persisted,
        "provider_options": ["openai", "deepseek", "glm", "minimax", "kimi"],
        "top_level": {
            "proxy_url": effective["proxy_url"],
            "dynamic_proxy_source_url": effective["dynamic_proxy_source_url"],
            "enabled_providers": effective["enabled_providers"],
            "search_keywords": effective["search_keywords"],
        },
    }


@app.post("/api/config/update")
def update_config(payload: dict, user: str = Depends(get_current_user)) -> dict:
    allowed_keys = {
        "proxy_url", "dynamic_proxy_source_url", "consumer_threads", "request_timeout",
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

    dynamic_proxy_source_url = payload.get("dynamic_proxy_source_url") or ""
    if dynamic_proxy_source_url:
        lines.append('DYNAMIC_PROXY_SOURCE_URL = "' + dynamic_proxy_source_url + '"')
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


@app.post("/api/proxy-source/fetch")
def fetch_dynamic_proxy(user: str = Depends(get_current_user)) -> dict:
    source_url = read_persisted_config().get("dynamic_proxy_source_url", "") or getattr(scanner_config, "dynamic_proxy_source_url", "")
    if not source_url:
        return {"ok": False, "message": "Dynamic proxy source URL is not configured"}

    pool = get_proxy_pool()
    if not pool:
        pool = init_proxy_pool([], dynamic_source_url=source_url)
    else:
        pool.set_dynamic_source(source_url)

    proxy_url = asyncio.run(pool.refresh_proxy())
    if not proxy_url:
        return {"ok": False, "message": "Failed to fetch a proxy from the dynamic source"}
    return {"ok": True, "proxy_url": proxy_url, "message": f"Fetched proxy: {proxy_url}"}

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
            "status": normalize_status_label(row["status"]),
            "balance": normalize_balance_text(row["balance"]),
            "source_url": normalize_display_text(row["source_url"] or ""),
            "model_tier": normalize_model_tier(row["model_tier"]),
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
    return {"items": [normalize_result_row(dict(row)) for row in rows]}


@app.get("/api/logs")
def logs(lines: int = Query(default=100, ge=10, le=500), user: str = Depends(get_current_user)) -> dict:
    raw_lines = read_log_lines(max(lines, 200))
    runtime_state = read_runtime_state()
    quota_items = get_github_quota()
    progress_lines = build_progress_lines(raw_lines, runtime_state, quota_items)
    progress_feed = normalize_progress_feed(progress_lines[-lines:])
    return {
        "lines": [entry["line"] for entry in progress_feed],
        "progress_feed": progress_feed,
        "raw_lines": raw_lines[-lines:],
    }


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
                    payload = normalize_progress_feed([newest])[0]
                    yield f"data: {json.dumps({'line': newest, 'entry': payload}, ensure_ascii=False)}\n\n"
            time.sleep(5)

    return StreamingResponse(generate(), media_type="text/event-stream")





