"""
UI module - Rich TUI dashboard.
"""

import json
import os
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Deque, List

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from config import config
from proxy_pool import get_proxy_pool


@dataclass
class DashboardStats:
    total_scanned: int = 0
    total_keys_found: int = 0
    candidates_discovered: int = 0
    repos_enqueued: int = 0
    repos_scanned: int = 0
    valid_keys: int = 0
    invalid_keys: int = 0
    quota_exceeded: int = 0
    connection_errors: int = 0
    error_keys: int = 0
    unverified_keys: int = 0
    queue_size: int = 0
    skipped_low_entropy: int = 0
    skipped_blacklist: int = 0
    skipped_sha: int = 0
    skipped_file_filter: int = 0
    skipped_existing: int = 0
    current_keyword: str = ""
    current_source: str = ""
    current_target: str = ""
    current_source_type: str = ""
    current_source_score: float = 0.0
    current_token_index: int = 0
    total_tokens: int = 0
    is_running: bool = True
    scan_run_id: str = ""
    round_number: int = 0
    round_keyword_index: int = 0
    round_total_keywords: int = 0
    round_scanned: int = 0
    round_keys_found: int = 0
    round_valid_keys: int = 0
    round_started_at: str = ""
    search_budget_total: int = 0
    search_budget_used: int = 0
    query_quality: dict = field(default_factory=dict)
    keys_by_source: dict = field(default_factory=dict)
    source_breakdown: dict = field(default_factory=dict)


@dataclass
class ValidKeyRecord:
    platform: str
    masked_key: str
    balance: str
    source: str
    found_time: str
    is_high_value: bool = False

    @property
    def platform_color(self) -> str:
        if self.is_high_value:
            return "bold gold1"
        colors = {
            "openai": "green",
            "azure": "blue",
            "anthropic": "magenta",
            "gemini": "cyan",
            "deepseek": "bright_blue",
            "glm": "bright_magenta",
            "minimax": "yellow",
            "kimi": "bright_cyan",
        }
        return colors.get(self.platform.lower(), "white")

    @property
    def balance_style(self) -> str:
        if self.is_high_value:
            return "bold green"
        if "$" in self.balance:
            return "bold cyan"
        return "green"


class Dashboard:
    def __init__(self):
        self.console = Console()
        self.stats = DashboardStats()
        self.valid_keys: List[ValidKeyRecord] = []
        self.logs: Deque[str] = deque(maxlen=20)
        self._lock = threading.RLock()
        self._live: Live | None = None
        self.state_file = Path(os.getenv("RUNTIME_STATE_PATH", "/app/output/runtime_state.json"))
        self.cumulative_file = Path(os.getenv("CUMULATIVE_STATS_PATH", "/app/output/cumulative_stats.json"))
        self._load_cumulative_stats()

    def _load_cumulative_stats(self):
        if not self.cumulative_file.exists():
            return
        try:
            data = json.loads(self.cumulative_file.read_text(encoding="utf-8"))
        except Exception:
            return
        for key in [
            "total_scanned",
            "total_keys_found",
            "candidates_discovered",
            "repos_enqueued",
            "repos_scanned",
            "valid_keys",
            "invalid_keys",
            "quota_exceeded",
            "connection_errors",
            "error_keys",
            "unverified_keys",
            "skipped_low_entropy",
            "skipped_blacklist",
            "skipped_sha",
            "skipped_file_filter",
            "skipped_existing",
        ]:
            value = data.get(key)
            if isinstance(value, int) and hasattr(self.stats, key):
                setattr(self.stats, key, value)

    def _write_cumulative_stats(self):
        payload = {
            "updated_at": datetime.now().isoformat(),
            "total_scanned": self.stats.total_scanned,
            "total_keys_found": self.stats.total_keys_found,
            "candidates_discovered": self.stats.candidates_discovered,
            "repos_enqueued": self.stats.repos_enqueued,
            "repos_scanned": self.stats.repos_scanned,
            "valid_keys": self.stats.valid_keys,
            "invalid_keys": self.stats.invalid_keys,
            "quota_exceeded": self.stats.quota_exceeded,
            "connection_errors": self.stats.connection_errors,
            "error_keys": self.stats.error_keys,
            "unverified_keys": self.stats.unverified_keys,
            "skipped_low_entropy": self.stats.skipped_low_entropy,
            "skipped_blacklist": self.stats.skipped_blacklist,
            "skipped_sha": self.stats.skipped_sha,
            "skipped_file_filter": self.stats.skipped_file_filter,
            "skipped_existing": self.stats.skipped_existing,
        }
        self.cumulative_file.parent.mkdir(parents=True, exist_ok=True)
        self.cumulative_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def _create_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["main"].split_row(Layout(name="left", ratio=1), Layout(name="right", ratio=2))
        layout["left"].split(Layout(name="stats", ratio=1))
        layout["right"].split(Layout(name="logs", size=10), Layout(name="table", ratio=1))
        return layout

    def _render_header(self) -> Panel:
        header_text = Text()
        header_text.append("Status: ", style="white")
        header_text.append("Running" if self.stats.is_running else "Stopped", style="bold green" if self.stats.is_running else "bold red")
        header_text.append("  | Tokens: ", style="white")
        header_text.append(str(self.stats.current_token_index + 1), style="bold cyan")
        header_text.append("/", style="white")
        header_text.append(str(self.stats.total_tokens), style="white")
        header_text.append("  | Source: ", style="white")
        header_text.append(self.stats.current_source or "idle", style="bold cyan")
        header_text.append("  | Proxy: ", style="white")
        header_text.append(config.proxy_url or "direct", style="bold cyan" if config.proxy_url else "bold yellow")
        return Panel(header_text, title="GitHub Secret Scanner Pro", title_align="center", border_style="cyan", box=box.ROUNDED)

    def _render_stats(self) -> Panel:
        stats_table = Table(show_header=False, box=None, padding=(0, 1))
        stats_table.add_column("Label", style="white")
        stats_table.add_column("Value", justify="right")
        rows = [
            ("Scanned files", self.stats.total_scanned, "cyan"),
            ("Candidates", self.stats.candidates_discovered, "bright_blue"),
            ("Queued repos", self.stats.repos_enqueued, "bright_blue"),
            ("Scanned repos", self.stats.repos_scanned, "blue"),
            ("Found keys", self.stats.total_keys_found, "yellow"),
            ("Valid", self.stats.valid_keys, "bold green"),
            ("Invalid", self.stats.invalid_keys, "red"),
            ("Quota hit", self.stats.quota_exceeded, "yellow"),
            ("Unverified", self.stats.unverified_keys or self.stats.queue_size, "blue"),
            ("Errors", self.stats.error_keys + self.stats.connection_errors, "magenta"),
        ]
        for label, value, color in rows:
            stats_table.add_row(Text(label, style="white"), Text(f"{value:,}", style=color))
        stats_table.add_row("", "")
        stats_table.add_row(Text("Keyword", style="dim"), Text((self.stats.current_keyword or "-")[:40], style="dim cyan"))
        stats_table.add_row(Text("Target", style="dim"), Text((self.stats.current_target or "-")[:40], style="dim cyan"))
        stats_table.add_row(Text("Budget", style="dim"), Text(f"{self.stats.search_budget_used}/{self.stats.search_budget_total}", style="dim"))
        return Panel(stats_table, title="Stats", border_style="white", box=box.ROUNDED)

    def _render_logs(self) -> Panel:
        from rich.text import Text as RichText
        log_text = RichText()
        for log_entry in list(self.logs):
            log_text.append_text(RichText.from_markup(log_entry + "\n"))
        if not self.logs:
            log_text.append("Waiting for logs...", style="dim")
        return Panel(log_text, title="Logs", border_style="white", box=box.ROUNDED)

    def _render_table(self) -> Panel:
        table = Table(show_header=True, header_style="bold white", box=box.SIMPLE, expand=True)
        table.add_column("Platform", style="bold", width=10)
        table.add_column("Key", width=20)
        table.add_column("Balance", width=15)
        table.add_column("Source", width=30)
        table.add_column("Time", width=10)
        for record in self.valid_keys[-10:]:
            if record.is_high_value:
                platform_text = Text(f"* {record.platform.upper()}", style="bold gold1")
                key_text = Text(record.masked_key, style="bold gold1")
                balance_text = Text(record.balance, style=record.balance_style)
            else:
                platform_text = Text(record.platform.upper(), style=record.platform_color)
                key_text = Text(record.masked_key, style=record.platform_color)
                balance_text = Text(record.balance, style=record.balance_style)
            table.add_row(platform_text, key_text, balance_text, record.source[:28] + "..." if len(record.source) > 30 else record.source, record.found_time)
        if not self.valid_keys:
            table.add_row(Text("--", style="dim"), Text("Waiting for valid keys...", style="dim"), Text("--", style="dim"), Text("--", style="dim"), Text("--", style="dim"))
        high_value_count = sum(1 for r in self.valid_keys if r.is_high_value)
        border_style = "gold1" if high_value_count > 0 else "green"
        title_prefix = f"High value {high_value_count} | " if high_value_count > 0 else ""
        return Panel(table, title=f"{title_prefix}Valid keys", border_style=border_style, box=box.ROUNDED)

    def _render_footer(self) -> Panel:
        footer_text = Text()
        footer_text.append("Current: ", style="white")
        footer_text.append((self.stats.current_keyword or "starting...")[:60], style="bold cyan")
        footer_text.append("  | Ctrl+C to stop", style="dim")
        return Panel(footer_text, border_style="dim", box=box.ROUNDED)

    def _render(self) -> Layout:
        layout = self._create_layout()
        with self._lock:
            layout["header"].update(self._render_header())
            layout["stats"].update(self._render_stats())
            layout["logs"].update(self._render_logs())
            layout["table"].update(self._render_table())
            layout["footer"].update(self._render_footer())
        return layout

    def add_log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        level_colors = {
            "INFO": "white",
            "SCAN": "cyan",
            "FOUND": "green",
            "VALID": "bold green",
            "HIGH": "bold gold1",
            "SKIP": "yellow",
            "WARN": "yellow",
            "ERROR": "red",
            "DEBUG": "dim",
        }
        color = level_colors.get(level, "white")
        formatted = f"[dim]{timestamp}[/] [{color}][{level}][/] {message}"
        with self._lock:
            self.logs.append(formatted)
        self.export_runtime_state()

    def add_valid_key(self, platform: str, masked_key: str, balance: str, source: str, is_high_value: bool = False, source_type: str = "validator"):
        record = ValidKeyRecord(
            platform=platform,
            masked_key=masked_key,
            balance=balance,
            source=source,
            found_time=datetime.now().strftime("%H:%M:%S"),
            is_high_value=is_high_value,
        )
        with self._lock:
            self.valid_keys.append(record)
            self.stats.valid_keys += 1
            self.stats.round_valid_keys += 1
            if self.stats.current_keyword:
                self._record_query_quality(self.stats.current_keyword, valid=1)
            self._increment_source_metric(source_type, "keys_valid", 1)
            if is_high_value:
                self.logs.append(f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] [bold gold1][HIGH][/] High value key: {platform.upper()} {masked_key}")
        self.export_runtime_state()

    def update_stats(self, **kwargs):
        direct_set_fields = {
            "current_token_index", "total_tokens", "queue_size", "round_number", "round_keyword_index",
            "round_total_keywords", "round_scanned", "round_keys_found", "round_valid_keys", "is_running",
            "current_keyword", "current_source", "current_target", "current_source_type", "current_source_score",
            "scan_run_id", "round_started_at", "search_budget_total", "search_budget_used",
        }
        with self._lock:
            for key, value in kwargs.items():
                if not hasattr(self.stats, key):
                    continue
                if key in direct_set_fields or isinstance(value, bool) or isinstance(value, str) or isinstance(value, float):
                    setattr(self.stats, key, value)
                elif isinstance(value, int):
                    setattr(self.stats, key, getattr(self.stats, key) + value)
                else:
                    setattr(self.stats, key, value)
        self.export_runtime_state()

    def increment_stat(self, stat_name: str, amount: int = 1):
        with self._lock:
            if hasattr(self.stats, stat_name):
                setattr(self.stats, stat_name, getattr(self.stats, stat_name) + amount)
            if stat_name == "total_scanned":
                self.stats.round_scanned += amount
            elif stat_name == "total_keys_found":
                self.stats.round_keys_found += amount
        self.export_runtime_state()

    def increment_source_found(self, source: str, amount: int = 1):
        with self._lock:
            self.stats.keys_by_source[source] = self.stats.keys_by_source.get(source, 0) + amount
            self._increment_source_metric(source, "keys_found", amount)
        self.export_runtime_state()

    def mark_source_activity(self, source: str, *, source_type: str = "", source_score: float | None = None, target: str = "", candidates_discovered: int = 0, repos_enqueued: int = 0, repos_scanned: int = 0, files_scanned: int = 0, keys_found: int = 0, keys_valid: int = 0, skipped: dict | None = None, budget_used: int = 0, budget_total: int | None = None, keyword: str = ""):
        with self._lock:
            if source:
                self.stats.current_source = source
            if source_type:
                self.stats.current_source_type = source_type
            if target:
                self.stats.current_target = target
            if keyword:
                self.stats.current_keyword = keyword
            if source_score is not None:
                self.stats.current_source_score = float(source_score)
            if budget_total is not None:
                self.stats.search_budget_total = int(budget_total)
            if budget_used:
                self.stats.search_budget_used += int(budget_used)
            self.stats.candidates_discovered += int(candidates_discovered)
            self.stats.repos_enqueued += int(repos_enqueued)
            self.stats.repos_scanned += int(repos_scanned)
            self.stats.total_scanned += int(files_scanned)
            self.stats.total_keys_found += int(keys_found)
            metric_pairs = {
                "candidates_discovered": candidates_discovered,
                "repos_enqueued": repos_enqueued,
                "repos_scanned": repos_scanned,
                "files_scanned": files_scanned,
                "keys_found": keys_found,
                "keys_valid": keys_valid,
            }
            for metric_name, metric_value in metric_pairs.items():
                if metric_value:
                    self._increment_source_metric(source, metric_name, int(metric_value))
            if skipped:
                for skip_name, skip_value in skipped.items():
                    if skip_value:
                        self._increment_source_metric(source, skip_name, int(skip_value))
        self.export_runtime_state()

    def _increment_source_metric(self, source: str, metric_name: str, amount: int = 1):
        if not source:
            return
        bucket = self.stats.source_breakdown.setdefault(source, {
            "candidates_discovered": 0,
            "repos_enqueued": 0,
            "repos_scanned": 0,
            "files_scanned": 0,
            "keys_found": 0,
            "keys_valid": 0,
            "skipped": {},
            "last_seen": "",
        })
        if metric_name.startswith("skipped_"):
            skipped_bucket = bucket.setdefault("skipped", {})
            skipped_bucket[metric_name] = skipped_bucket.get(metric_name, 0) + amount
        else:
            bucket[metric_name] = bucket.get(metric_name, 0) + amount
        bucket["last_seen"] = datetime.now().isoformat()

    def start_scan_run(self, scan_run_id: str, round_number: int, total_keywords: int):
        with self._lock:
            self.stats.scan_run_id = scan_run_id
            self.stats.round_number = round_number
            self.stats.round_keyword_index = 0
            self.stats.round_total_keywords = total_keywords
            self.stats.round_scanned = 0
            self.stats.round_keys_found = 0
            self.stats.round_valid_keys = 0
            self.stats.round_started_at = datetime.now().isoformat()
            self.stats.search_budget_used = 0
            self.stats.current_source = ""
            self.stats.current_target = ""
            self.stats.current_source_type = ""
            self.stats.current_source_score = 0.0
            self.logs.clear()
            self.logs.append(f"[dim]{datetime.now().strftime('%H:%M:%S')}[/] [cyan][SCAN][/] Scan run started: {scan_run_id}")
        self.export_runtime_state()

    def _record_query_quality(self, keyword: str, scanned: int = 0, found: int = 0, valid: int = 0):
        if not keyword:
            return
        bucket = self.stats.query_quality.setdefault(keyword, {"scanned": 0, "found": 0, "valid": 0, "score": 0.0, "last_seen": ""})
        bucket["scanned"] += int(scanned)
        bucket["found"] += int(found)
        bucket["valid"] += int(valid)
        if bucket["scanned"] > 0:
            bucket["score"] = round((bucket["valid"] * 3 + bucket["found"]) / bucket["scanned"], 4)
        bucket["last_seen"] = datetime.now().isoformat()
        if len(self.stats.query_quality) > 256:
            self.stats.query_quality = dict(sorted(self.stats.query_quality.items(), key=lambda item: (item[1].get("score", 0), item[1].get("valid", 0), item[1].get("found", 0)), reverse=True)[:256])
        self.export_runtime_state()

    def export_runtime_state(self):
        with self._lock:
            proxy_pool = get_proxy_pool()
            payload = {
                "updated_at": datetime.now().isoformat(),
                "current_run": {
                    "is_running": self.stats.is_running,
                    "scan_run_id": self.stats.scan_run_id,
                    "round_number": self.stats.round_number,
                    "round_keyword_index": self.stats.round_keyword_index,
                    "round_total_keywords": self.stats.round_total_keywords,
                    "round_scanned": self.stats.round_scanned,
                    "round_keys_found": self.stats.round_keys_found,
                    "round_valid_keys": self.stats.round_valid_keys,
                    "round_started_at": self.stats.round_started_at,
                    "current_keyword": self.stats.current_keyword,
                    "current_source": self.stats.current_source,
                    "current_target": self.stats.current_target,
                    "current_source_type": self.stats.current_source_type,
                    "current_source_score": self.stats.current_source_score,
                    "current_token_index": self.stats.current_token_index,
                    "total_tokens": self.stats.total_tokens,
                    "queue_size": self.stats.queue_size,
                    "search_budget_total": self.stats.search_budget_total,
                    "search_budget_used": self.stats.search_budget_used,
                },
                "counters": {
                    "total_scanned": self.stats.total_scanned,
                    "total_keys_found": self.stats.total_keys_found,
                    "candidates_discovered": self.stats.candidates_discovered,
                    "repos_enqueued": self.stats.repos_enqueued,
                    "repos_scanned": self.stats.repos_scanned,
                    "valid_keys": self.stats.valid_keys,
                    "invalid_keys": self.stats.invalid_keys,
                    "quota_exceeded_total": self.stats.quota_exceeded,
                    "connection_errors": self.stats.connection_errors,
                    "error_total": self.stats.error_keys,
                    "unverified_total": self.stats.unverified_keys,
                    "skipped_low_entropy": self.stats.skipped_low_entropy,
                    "skipped_blacklist": self.stats.skipped_blacklist,
                    "skipped_sha": self.stats.skipped_sha,
                    "skipped_file_filter": self.stats.skipped_file_filter,
                    "skipped_existing": self.stats.skipped_existing,
                },
                "quality": {
                    "keys_by_source": dict(self.stats.keys_by_source),
                    "source_breakdown": dict(self.stats.source_breakdown),
                    "query_quality": dict(self.stats.query_quality),
                },
                "stats": {
                    "total_scanned": self.stats.total_scanned,
                    "total_keys_found": self.stats.total_keys_found,
                    "candidates_discovered": self.stats.candidates_discovered,
                    "repos_enqueued": self.stats.repos_enqueued,
                    "repos_scanned": self.stats.repos_scanned,
                    "valid_keys": self.stats.valid_keys,
                    "invalid_keys": self.stats.invalid_keys,
                    "quota_exceeded": self.stats.quota_exceeded,
                    "connection_errors": self.stats.connection_errors,
                    "error_keys": self.stats.error_keys,
                    "unverified_keys": self.stats.unverified_keys,
                    "queue_size": self.stats.queue_size,
                    "skipped_low_entropy": self.stats.skipped_low_entropy,
                    "skipped_blacklist": self.stats.skipped_blacklist,
                    "skipped_sha": self.stats.skipped_sha,
                    "skipped_file_filter": self.stats.skipped_file_filter,
                    "skipped_existing": self.stats.skipped_existing,
                    "current_keyword": self.stats.current_keyword,
                    "current_source": self.stats.current_source,
                    "current_target": self.stats.current_target,
                    "current_source_type": self.stats.current_source_type,
                    "current_source_score": self.stats.current_source_score,
                    "current_token_index": self.stats.current_token_index,
                    "total_tokens": self.stats.total_tokens,
                    "is_running": self.stats.is_running,
                    "scan_run_id": self.stats.scan_run_id,
                    "round_number": self.stats.round_number,
                    "round_keyword_index": self.stats.round_keyword_index,
                    "round_total_keywords": self.stats.round_total_keywords,
                    "round_scanned": self.stats.round_scanned,
                    "round_keys_found": self.stats.round_keys_found,
                    "round_valid_keys": self.stats.round_valid_keys,
                    "round_started_at": self.stats.round_started_at,
                    "search_budget_total": self.stats.search_budget_total,
                    "search_budget_used": self.stats.search_budget_used,
                    "keys_by_source": dict(self.stats.keys_by_source),
                    "source_breakdown": dict(self.stats.source_breakdown),
                    "query_quality": dict(self.stats.query_quality),
                },
                "recent_logs": list(self.logs),
                "proxy_pool": (
                    {"enabled": True, **proxy_pool.get_stats()}
                    if proxy_pool
                    else {"enabled": False, "total": 0, "healthy": 0, "unhealthy": 0, "proxies": []}
                ),
                "valid_keys": [
                    {
                        "platform": record.platform,
                        "masked_key": record.masked_key,
                        "balance": record.balance,
                        "source": record.source,
                        "found_time": record.found_time,
                        "is_high_value": record.is_high_value,
                    }
                    for record in self.valid_keys[-10:]
                ],
            }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        self._write_cumulative_stats()

    def start(self) -> Live:
        self._live = Live(self._render(), console=self.console, refresh_per_second=4, screen=True)
        return self._live

    def refresh(self):
        if self._live:
            self._live.update(self._render())

    def stop(self):
        with self._lock:
            self.stats.is_running = False
        self.export_runtime_state()


dashboard = Dashboard()
