#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Git clone scanner source.

High-value discovery priority:
  Tier 1 - fresh GitHub events
  Tier 2 - newly created repos
  Tier 3 - repos that disappeared shortly after discovery
  Tier 4 - code search fallback only when candidates are insufficient
"""

import json
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from loguru import logger

from config import config
from database import Database
from scanner import ScanResult, is_test_key, should_skip_file


TARGET_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".env.local", ".env.production", ".env.development",
    ".yml", ".yaml", ".toml",
    ".sh", ".bash", ".zsh",
    ".php", ".rb", ".go", ".rs", ".java",
    ".conf", ".cfg", ".ini",
    ".json", ".xml",
}

TARGET_FILENAME_KEYWORDS: Set[str] = {
    "dockerfile", "secret", "credential", "token", "key", "password",
    "config", "setting", "env", ".env",
}

MAX_REPOS_PER_ROUND = 30
MAX_GIT_DIR_MB = 50
SHOW_BATCH_SIZE = 50
EVENT_TYPES_WANTED = {"CreateEvent", "PushEvent", "PublicEvent"}
SEARCH_KEYWORDS = [
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "BIGMODEL_API_KEY",
    "MINIMAX_API_KEY",
    "MOONSHOT_API_KEY",
    "sk-proj-",
    "chatglm",
    "glm-4",
    "minimax",
    "kimi",
    "moonshot",
]


@dataclass
class RepoTarget:
    full_name: str
    clone_url: str
    html_url: str
    stars: int = 0
    description: str = ""
    language: str = ""
    detected_by: str = ""
    source_type: str = ""
    source_priority: int = 99
    source_score: float = 0.0
    first_seen_at: float = field(default_factory=time.time)


class GitCloneScanner:
    def __init__(
        self,
        result_queue: queue.Queue,
        db: Database,
        stop_event: threading.Event,
        dashboard=None,
        clone_dir: Optional[str] = None,
    ):
        self.result_queue = result_queue
        self.db = db
        self.stop_event = stop_event
        self.dashboard = dashboard
        self._clone_root = Path(clone_dir) if clone_dir else Path(tempfile.mkdtemp(prefix="gh_scanner_"))
        self._clone_root.mkdir(parents=True, exist_ok=True)
        self._scanned_repos: Set[str] = set()
        self._scanned_lock = threading.Lock()
        self._seen_event_ids: Set[str] = set()
        self._known_repos: Dict[str, float] = {}
        self._known_repos_lock = threading.Lock()
        self._token_idx = 0
        self._stats = {
            "repos_from_events": 0,
            "repos_from_search_created": 0,
            "repos_from_code_search": 0,
            "repos_cloned": 0,
            "repos_deleted_after_pull": 0,
            "repos_skipped_too_large": 0,
            "files_scanned": 0,
            "keys_found": 0,
        }

        from config import REGEX_PATTERNS
        self._key_patterns: Dict[str, re.Pattern] = {}
        for platform, pattern in REGEX_PATTERNS.items():
            try:
                self._key_patterns[platform] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                logger.warning(f"GitClone: invalid regex skipped [{platform}]")

    def run(self):
        logger.info(f"[GitClone] scanner started (work dir: {self._clone_root})")
        tokens = config.github_tokens
        if not tokens or not any(tokens):
            logger.info("[GitClone] no token configured, using anonymous mode")

        round_num = 0
        code_search_budget = int(os.getenv("GIT_CLONE_CODE_SEARCH_BUDGET", "4"))
        while not self.stop_event.is_set():
            round_num += 1
            logger.info(f"[GitClone] === round {round_num} ===")

            candidates: List[RepoTarget] = []
            for discover in (self._discover_from_events, self._discover_recent_repos):
                try:
                    candidates.extend(discover(tokens))
                except Exception as exc:
                    logger.debug(f"[GitClone] discover failed: {exc}")
            try:
                candidates.extend(self._discover_deleted_repos())
            except Exception as exc:
                logger.debug(f"[GitClone] deleted repo discover failed: {exc}")

            if len(candidates) < 10:
                try:
                    candidates.extend(self._discover_from_code_search(tokens, budget=code_search_budget))
                except Exception as exc:
                    logger.debug(f"[GitClone] code search fallback failed: {exc}")

            deduped = self._dedupe_candidates(candidates)
            deduped.sort(key=lambda repo: (repo.source_priority, -repo.source_score, -repo.first_seen_at, -repo.stars, repo.full_name.lower()))
            scheduled = deduped[:MAX_REPOS_PER_ROUND]

            if self.dashboard and hasattr(self.dashboard, "mark_source_activity"):
                self.dashboard.mark_source_activity(
                    "git_clone",
                    source_type="priority_queue",
                    candidates_discovered=len(candidates),
                    repos_enqueued=len(scheduled),
                    budget_total=code_search_budget,
                )

            logger.info(f"[GitClone] queued {len(scheduled)} repos this round")
            for index, repo in enumerate(scheduled, start=1):
                if self.stop_event.is_set():
                    break
                logger.info(f"[GitClone]   [{index}/{len(scheduled)}] {repo.detected_by}: {repo.full_name}")
                self._scan_one_repo(repo)

            if not self.stop_event.is_set():
                logger.info("[GitClone] round complete, sleeping 120s")
                for _ in range(120):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)

        self._cleanup()
        logger.info(f"[GitClone] scanner stopped: {self._stats}")

    def _dedupe_candidates(self, candidates: List[RepoTarget]) -> List[RepoTarget]:
        seen_in_round = set()
        deduped: List[RepoTarget] = []
        for repo in candidates:
            key = repo.full_name.lower()
            with self._scanned_lock:
                if key in self._scanned_repos:
                    continue
            if key in seen_in_round:
                continue
            seen_in_round.add(key)
            deduped.append(repo)
        return deduped

    def _discover_from_events(self, tokens: List[str]) -> List[RepoTarget]:
        repos: List[RepoTarget] = []
        headers = self._make_headers(tokens)
        req = urllib.request.Request("https://api.github.com/events?per_page=100", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                events = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                logger.info("[GitClone] events API rate limited")
                time.sleep(10)
            return repos
        except Exception as exc:
            logger.debug(f"[GitClone] events error: {exc}")
            return repos

        for event in events:
            event_id = event.get("id", "")
            if not event_id or event_id in self._seen_event_ids:
                continue
            self._seen_event_ids.add(event_id)
            if event.get("type", "") not in EVENT_TYPES_WANTED:
                continue
            repo_data = event.get("repo", {}) or event.get("repository", {}) or {}
            full_name = repo_data.get("name") or repo_data.get("full_name") or ""
            if not full_name:
                continue
            with self._known_repos_lock:
                self._known_repos.setdefault(full_name.lower(), time.time())
            repos.append(RepoTarget(
                full_name=full_name,
                clone_url=f"https://github.com/{full_name}.git",
                html_url=f"https://github.com/{full_name}",
                detected_by="events",
                source_type="event_fresh_repo",
                source_priority=1,
                source_score=100.0,
            ))
        self._stats["repos_from_events"] += len(repos)
        return repos

    def _discover_recent_repos(self, tokens: List[str]) -> List[RepoTarget]:
        repos: List[RepoTarget] = []
        headers = self._make_headers(tokens)
        broad_queries = [
            "env OR token OR secret OR api key OR OPENAI OR deepseek OR moonshot OR glm OR minimax",
            "config OR credential OR password OR .env OR bigmodel OR kimi",
        ]
        for query in broad_queries:
            if self.stop_event.is_set():
                break
            try:
                url = (
                    "https://api.github.com/search/repositories"
                    f"?q={urllib.parse.quote(query)}&sort=created&order=desc&per_page=50"
                )
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    time.sleep(5)
                continue
            except Exception as exc:
                logger.debug(f"[GitClone] recent repo error: {exc}")
                continue

            for item in data.get("items", []):
                full_name = item.get("full_name", "")
                if not full_name:
                    continue
                with self._known_repos_lock:
                    self._known_repos.setdefault(full_name.lower(), time.time())
                repos.append(RepoTarget(
                    full_name=full_name,
                    clone_url=f"https://github.com/{full_name}.git",
                    html_url=item.get("html_url", f"https://github.com/{full_name}"),
                    stars=item.get("stargazers_count", 0),
                    description=item.get("description", "") or "",
                    language=item.get("language", "") or "",
                    detected_by="search_created",
                    source_type="recent_repo",
                    source_priority=2,
                    source_score=80.0 + min(item.get("stargazers_count", 0), 20),
                ))
            time.sleep(0.3)
        self._stats["repos_from_search_created"] += len(repos)
        return repos

    def _discover_deleted_repos(self) -> List[RepoTarget]:
        deleted: List[RepoTarget] = []
        now = time.time()
        to_check: List[str] = []
        with self._known_repos_lock:
            for name, first_seen in self._known_repos.items():
                if now - first_seen > 3600:
                    to_check.append(name)
        for full_name in to_check[:20]:
            if self.stop_event.is_set():
                break
            try:
                req = urllib.request.Request(f"https://github.com/{full_name}", headers={"User-Agent": "Mozilla/5.0"}, method="HEAD")
                with urllib.request.urlopen(req, timeout=10):
                    pass
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    with self._scanned_lock:
                        if full_name not in self._scanned_repos:
                            deleted.append(RepoTarget(
                                full_name=full_name,
                                clone_url=f"https://github.com/{full_name}.git",
                                html_url=f"https://github.com/{full_name}",
                                detected_by="deleted_repo",
                                source_type="deleted_repo",
                                source_priority=1,
                                source_score=95.0,
                            ))
                            self._stats["repos_deleted_after_pull"] += 1
            except Exception:
                pass
            time.sleep(0.2)
        return deleted

    def _discover_from_code_search(self, tokens: List[str], budget: int = 4) -> List[RepoTarget]:
        repos: List[RepoTarget] = []
        seen_full_names = set()
        headers = self._make_headers(tokens)
        for keyword in SEARCH_KEYWORDS[:budget]:
            if self.stop_event.is_set():
                break
            try:
                url = (
                    "https://api.github.com/search/repositories"
                    f"?q={urllib.parse.quote(keyword)}&sort=stars&order=desc&per_page=30"
                )
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    time.sleep(10)
                continue
            except Exception as exc:
                logger.debug(f"[GitClone] code search fallback error: {exc}")
                continue

            for item in data.get("items", []):
                full_name = item.get("full_name", "")
                if not full_name or full_name in seen_full_names:
                    continue
                seen_full_names.add(full_name)
                repos.append(RepoTarget(
                    full_name=full_name,
                    clone_url=f"https://github.com/{full_name}.git",
                    html_url=item.get("html_url", f"https://github.com/{full_name}"),
                    stars=item.get("stargazers_count", 0),
                    description=item.get("description", "") or "",
                    language=item.get("language", "") or "",
                    detected_by="code_search",
                    source_type="code_search_fallback",
                    source_priority=4,
                    source_score=20.0 + min(item.get("stargazers_count", 0), 10),
                ))
            time.sleep(0.5)
        self._stats["repos_from_code_search"] += len(repos)
        return repos

    def _make_headers(self, tokens: List[str]) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-Secret-Scanner/2.0",
        }
        if tokens:
            idx = self._token_idx % len(tokens)
            self._token_idx = idx + 1
            headers["Authorization"] = f"token {tokens[idx]}"
        return headers

    def _scan_one_repo(self, repo: RepoTarget):
        repo_key = repo.full_name.lower()
        with self._scanned_lock:
            if repo_key in self._scanned_repos:
                return
            self._scanned_repos.add(repo_key)

        repo_dir_safe = repo.full_name.replace("/", "__")
        work_dir = self._clone_root / repo_dir_safe
        try:
            if not self._partial_clone(repo.clone_url, work_dir):
                return
            self._stats["repos_cloned"] += 1
            if self.dashboard and hasattr(self.dashboard, "mark_source_activity"):
                self.dashboard.mark_source_activity(
                    "git_clone",
                    source_type=repo.source_type or repo.detected_by,
                    target=repo.full_name,
                    source_score=repo.source_score,
                    repos_scanned=1,
                )

            git_size = self._estimate_git_dir(work_dir)
            if git_size is not None and git_size > MAX_GIT_DIR_MB:
                logger.info(f"[GitClone] .git {git_size}MB exceeds limit, skip")
                self._stats["repos_skipped_too_large"] += 1
                shutil.rmtree(work_dir, ignore_errors=True)
                return

            target_files = self._list_target_files(work_dir)
            if not target_files:
                shutil.rmtree(work_dir, ignore_errors=True)
                return
            self._batch_scan_files(work_dir, target_files, repo)
        except Exception as exc:
            logger.debug(f"[GitClone] scan error {repo.full_name}: {exc}")
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _partial_clone(self, clone_url: str, target_dir: Path) -> bool:
        try:
            result = subprocess.run(
                [
                    "git", "clone",
                    "--filter=blob:none",
                    "--depth=1",
                    "--single-branch",
                    "--no-checkout",
                    "--quiet",
                    clone_url, str(target_dir),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            logger.error("[GitClone] git command not available")
            return False
        except Exception:
            return False

    def _estimate_git_dir(self, repo_dir: Path) -> Optional[int]:
        git_dir = repo_dir / ".git"
        if not git_dir.exists():
            return None
        try:
            total = sum(f.stat().st_size for f in git_dir.rglob("*") if f.is_file())
            return total // (1024 * 1024)
        except Exception:
            return None

    def _list_target_files(self, repo_dir: Path) -> List[str]:
        target_files: List[str] = []
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "ls-tree", "-r", "HEAD", "--name-only"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return []
            for file_path in result.stdout.splitlines():
                if not file_path.strip():
                    continue
                ext = Path(file_path).suffix.lower()
                if ext in TARGET_EXTENSIONS:
                    target_files.append(file_path)
                    continue
                fname = Path(file_path).name.lower()
                if any(keyword in fname for keyword in TARGET_FILENAME_KEYWORDS):
                    target_files.append(file_path)
        except Exception:
            return []
        return target_files

    def _batch_scan_files(self, repo_dir: Path, file_paths: List[str], repo: RepoTarget):
        self._stats["files_scanned"] += len(file_paths)
        if self.dashboard and hasattr(self.dashboard, "mark_source_activity"):
            self.dashboard.mark_source_activity(
                "git_clone",
                source_type=repo.source_type or repo.detected_by,
                files_scanned=len(file_paths),
                target=repo.full_name,
                source_score=repo.source_score,
            )

        for index in range(0, len(file_paths), SHOW_BATCH_SIZE):
            if self.stop_event.is_set():
                break
            batch = file_paths[index:index + SHOW_BATCH_SIZE]
            contents = self._batch_get_contents(repo_dir, batch)
            for file_path, content in zip(batch, contents):
                if content is None:
                    continue
                skip, _skip_reason = should_skip_file(file_path, len(content.encode("utf-8")))
                if skip:
                    continue
                source_url = f"{repo.html_url}/blob/main/{file_path}"
                for platform, pattern in self._key_patterns.items():
                    if self.stop_event.is_set():
                        return
                    for match in pattern.finditer(content):
                        api_key = match.group()
                        if is_test_key(api_key):
                            continue
                        start = max(0, match.start() - 100)
                        end = min(len(content), match.end() + 100)
                        result = ScanResult(
                            platform=platform,
                            api_key=api_key,
                            base_url="",
                            source_url=source_url,
                            context=content[start:end],
                        )
                        self._put_result(result)

    def _batch_get_contents(self, repo_dir: Path, file_paths: List[str]) -> List[Optional[str]]:
        results: List[Optional[str]] = []
        for file_path in file_paths:
            if self.stop_event.is_set():
                results.append(None)
                continue
            try:
                result = subprocess.run(
                    ["git", "-C", str(repo_dir), "show", f"HEAD:{file_path}"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                results.append(result.stdout if result.returncode == 0 and result.stdout else None)
            except Exception:
                results.append(None)
        return results

    def _put_result(self, result: ScanResult):
        try:
            self.result_queue.put_nowait(result)
        except Exception:
            try:
                self.result_queue.put(result, timeout=5)
            except Exception:
                return
        self._stats["keys_found"] += 1
        if self.dashboard and hasattr(self.dashboard, "mark_source_activity"):
            self.dashboard.mark_source_activity("git_clone", source_type="repo_scan", keys_found=1, target=result.source_url)

    def _cleanup(self):
        try:
            if str(self._clone_root).startswith(tempfile.gettempdir()) or str(self._clone_root).startswith("/tmp"):
                shutil.rmtree(self._clone_root, ignore_errors=True)
        except Exception:
            pass


def start_git_clone_scanner(
    result_queue: queue.Queue,
    db: Database,
    stop_event: threading.Event,
    dashboard=None,
    clone_dir: Optional[str] = None,
) -> threading.Thread:
    scanner = GitCloneScanner(
        result_queue=result_queue,
        db=db,
        stop_event=stop_event,
        dashboard=dashboard,
        clone_dir=clone_dir,
    )
    thread = threading.Thread(target=scanner.run, name="GitCloneScanner", daemon=True)
    thread.start()
    return thread
