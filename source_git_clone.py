#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Git 克隆扫描源 — 用 Git partial clone + 时间线监测，捕捉新仓库和已删除仓库

发现策略优先级（从高到低）：
  Tier 1 — GitHub Events 实时推送流
    监听 CreateEvent / PushEvent / PublicEvent，clone 刚出现的新仓库。
    这些仓库可能几分钟后就被删除，我们在消失前就拉下来了。

  Tier 2 — 按创建时间排序搜索
    GitHub Search /repositories?sort=created&order=desc
    搜索刚创建几分钟/几小时的仓库，优先于所有老仓库。

  Tier 3 — 删除检测
    GitHub 删除仓库后会返回 404，但我们已经 partial clone 了本地副本。
    通过定期重试 404 的旧 URL 来发现"刚被删除"的仓库。

  Tier 4 — 传统 Code Search（兜底）
    只在以上三层产出不足时触发，通过 keyword 搜索补量。

用法：
  python main.py --git                      # 启用 Git clone 扫描源
  python main.py --git --git-clone-dir D:\tmp\scanner_cache
"""

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import queue
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple, Dict
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

from config import config
from database import Database
from scanner import (
    ScanResult,
    should_skip_file,
    calculate_entropy,
    is_test_key,
)


# ============================================================================
#                              配置
# ============================================================================

# 目标文件扩展名白名单
TARGET_EXTENSIONS: Set[str] = {
    '.py', '.js', '.ts', '.jsx', '.tsx',
    '.env', '.env.local', '.env.production', '.env.development',
    '.yml', '.yaml', '.toml',
    '.sh', '.bash', '.zsh',
    '.php', '.rb', '.go', '.rs', '.java',
    '.conf', '.cfg', '.ini',
    '.json', '.xml',
}

# 目标文件名关键词
TARGET_FILENAME_KEYWORDS: Set[str] = {
    'dockerfile', 'secret', 'credential', 'token', 'key', 'password',
    'config', 'setting', 'env', '.env',
}

# 每轮扫描最多处理的仓库数
MAX_REPOS_PER_ROUND = 30

# 并行 clone 上限
MAX_CONCURRENT_CLONES = 4

# 单个仓库最大 .git 目录大小
MAX_GIT_DIR_MB = 50

# 单次 git show 批量提取的文件数
SHOW_BATCH_SIZE = 50

# 搜索关键词（用于 Tier 2 按创建时间排序和 Tier 4 兜底）
SEARCH_KEYWORDS = [
    "OPENAI_API_KEY", "sk-proj-", "sk-",
    "ANTHROPIC_API_KEY", "sk-ant-",
    "AIzaSy", "hf_", "gsk_",
    "DEEPSEEK_API_KEY", "HUGGINGFACE_TOKEN",
    "OPENAI_BASE_URL", "AIPROXY_TOKEN",
]

# 事件类型白名单（Tier 1）
EVENT_TYPES_WANTED = {"CreateEvent", "PushEvent", "PublicEvent"}


# ============================================================================
#                          数据模型
# ============================================================================

@dataclass
class RepoTarget:
    """扫描目标仓库"""
    full_name: str          # owner/repo
    clone_url: str          # https://github.com/owner/repo.git
    html_url: str           # https://github.com/owner/repo
    stars: int = 0
    description: str = ""
    language: str = ""
    detected_by: str = ""   # 发现方式: events / search_created / code_search


# ============================================================================
#                          Git Clone 扫描器
# ============================================================================

class GitCloneScanner:
    """用 Git partial clone + 时间线监测扫描仓库泄露的密钥"""

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

        # 临时工作目录
        self._clone_root = Path(clone_dir) if clone_dir else Path(tempfile.mkdtemp(prefix="gh_scanner_"))
        self._clone_root.mkdir(parents=True, exist_ok=True)

        # 已扫描的 repo
        self._scanned_repos: Set[str] = set()
        self._scanned_lock = threading.Lock()

        # 已见过的 Event ID（去重）
        self._seen_event_ids: Set[str] = set()

        # 已看到的仓库 + 质量评分，用于检测删除
        self._known_repos: Dict[str, float] = {}  # full_name -> first_seen_timestamp
        self._known_repos_lock = threading.Lock()

        # Token 轮询
        self._token_idx = 0

        # 统计
        self._stats = {
            'repos_from_events': 0,
            'repos_from_search_created': 0,
            'repos_from_code_search': 0,
            'repos_cloned': 0,
            'repos_deleted_after_pull': 0,
            'repos_skipped_too_large': 0,
            'files_scanned': 0,
            'keys_found': 0,
        }

        # 编译正则
        from config import REGEX_PATTERNS
        self._key_patterns: Dict[str, re.Pattern] = {}
        for platform, pattern in REGEX_PATTERNS.items():
            try:
                self._key_patterns[platform] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                logger.warning(f"GitClone: 跳过无效正则 [{platform}]: {pattern}")

    # ====================================================================
    #  对外入口
    # ====================================================================

    def run(self):
        """主运行逻辑 —— 分层发现，层级越高优先级越高"""
        logger.info(f"[GitClone] 扫描器启动 (工作目录: {self._clone_root})")

        tokens = config.github_tokens
        if not tokens or not any(tokens):
            logger.info("[GitClone] 未配置 Token, 使用匿名模式 (限流 60次/小时)")

        # ---- 循环：每次轮换 Tier 1~3，Tier 4 兜底 ----
        round_num = 0
        while not self.stop_event.is_set():
            round_num += 1
            logger.info(f"[GitClone] === 第 {round_num} 轮 ===")

            candidates = []

            # Tier 1: Events 实时推送流（最高优先级）
            try:
                events_repos = self._discover_from_events(tokens)
                candidates.extend(events_repos)
                logger.info(f"[GitClone] Tier1 Events: 发现 {len(events_repos)} 个新仓库")
            except Exception as exc:
                logger.debug(f"[GitClone] Tier1 失败: {exc}")

            # Tier 2: 按创建时间排序搜索（新仓库）
            try:
                created_repos = self._discover_recent_repos(tokens)
                candidates.extend(created_repos)
                logger.info(f"[GitClone] Tier2 新仓库搜索: 发现 {len(created_repos)} 个")
            except Exception as exc:
                logger.debug(f"[GitClone] Tier2 失败: {exc}")

            # Tier 3: 检测被删除的仓库
            try:
                deleted_repos = self._discover_deleted_repos()
                candidates.extend(deleted_repos)
                if deleted_repos:
                    logger.info(f"[GitClone] Tier3 已删除仓库: 发现 {len(deleted_repos)} 个")
            except Exception as exc:
                logger.debug(f"[GitClone] Tier3 失败: {exc}")

            # Tier 4: 兜底 — Code Search
            if len(candidates) < 10:
                try:
                    code_repos = self._discover_from_code_search(tokens)
                    candidates.extend(code_repos)
                    logger.info(f"[GitClone] Tier4 CodeSearch: 发现 {len(code_repos)} 个")
                except Exception as exc:
                    logger.debug(f"[GitClone] Tier4 失败: {exc}")

            # 去重 + 限数
            seen_in_round = set()
            deduped = []
            for r in candidates:
                key = r.full_name.lower()
                with self._scanned_lock:
                    if key in self._scanned_repos:
                        continue
                if key in seen_in_round:
                    continue
                seen_in_round.add(key)
                deduped.append(r)

            logger.info(f"[GitClone] 本轮共 {len(deduped)} 个待扫描仓库（去重后）")

            # 扫描每个仓库
            for idx, repo in enumerate(deduped[:MAX_REPOS_PER_ROUND]):
                if self.stop_event.is_set():
                    break
                logger.info(f"[GitClone]   [{idx+1}/{len(deduped)}] {repo.detected_by}: {repo.full_name}")
                self._scan_one_repo(repo)

            # 轮间等待（避免空转）
            if not self.stop_event.is_set():
                logger.info(f"[GitClone] 本轮完成，等待 120 秒后下一轮")
                for _ in range(120):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)

        self._cleanup()
        logger.info(f"[GitClone] 扫描结束: {self._stats}")

    # ====================================================================
    #  Tier 1: GitHub Events 实时推送流
    # ====================================================================

    def _discover_from_events(self, tokens: List[str]) -> List[RepoTarget]:
        """监听 GitHub 公开时间线，捕捉刚被创建/推送的仓库"""
        repos = []
        headers = self._make_headers(tokens)

        try:
            # 请求 GitHub 公开事件时间线
            req = urllib.request.Request(
                "https://api.github.com/events?per_page=100",
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                events = json.loads(resp.read().decode())

            for event in events:
                event_id = event.get("id", "")
                if not event_id or event_id in self._seen_event_ids:
                    continue
                self._seen_event_ids.add(event_id)

                etype = event.get("type", "")
                if etype not in EVENT_TYPES_WANTED:
                    continue

                repo_data = event.get("repo", {}) or {}
                full_name = repo_data.get("name", "")
                if not full_name:
                    repo_data = event.get("repository", {})
                    full_name = repo_data.get("full_name", "")

                if not full_name:
                    continue

                # 记录到已知仓库（用于删除检测）
                with self._known_repos_lock:
                    if full_name.lower() not in self._known_repos:
                        self._known_repos[full_name.lower()] = time.time()

                repos.append(RepoTarget(
                    full_name=full_name,
                    clone_url=f"https://github.com/{full_name}.git",
                    html_url=f"https://github.com/{full_name}",
                    stars=0,
                    detected_by="events",
                ))

            self._stats['repos_from_events'] += len(repos)

        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                logger.info("[GitClone] Tier1 Events API 限流，等待恢复")
                time.sleep(10)
        except Exception as exc:
            logger.debug(f"[GitClone] Tier1 异常: {exc}")

        return repos

    # ====================================================================
    #  Tier 2: 按创建时间排序搜索新仓库
    # ====================================================================

    def _discover_recent_repos(self, tokens: List[str]) -> List[RepoTarget]:
        """搜索 GitHub 最近创建的仓库（sort=created&order=desc）"""
        repos = []
        headers = self._make_headers(tokens)

        # 用宽泛的关键词搜仓库，按创建时间倒序
        broad_queries = [
            "env OR token OR secret OR api key OR OPENAI",
            "config OR credential OR password OR .env",
            "created:>=2026-01-01",
        ]

        for query in broad_queries:
            if self.stop_event.is_set():
                break
            try:
                url = (
                    f"https://api.github.com/search/repositories"
                    f"?q={urllib.parse.quote(query)}"
                    f"&sort=created&order=desc&per_page=100"
                )
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())

                for item in data.get("items", []):
                    full_name = item.get("full_name", "")
                    if not full_name:
                        continue

                    # 记录到已知仓库
                    with self._known_repos_lock:
                        if full_name.lower() not in self._known_repos:
                            self._known_repos[full_name.lower()] = time.time()

                    repos.append(RepoTarget(
                        full_name=full_name,
                        clone_url=f"https://github.com/{full_name}.git",
                        html_url=item.get("html_url", f"https://github.com/{full_name}"),
                        stars=item.get("stargazers_count", 0),
                        description=item.get("description", "") or "",
                        language=item.get("language", "") or "",
                        detected_by="search_created",
                    ))

                # 温柔限速
                time.sleep(0.3)

            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    time.sleep(5)
            except Exception as exc:
                logger.debug(f"[GitClone] Tier2 搜索异常: {exc}")

        self._stats['repos_from_search_created'] += len(repos)
        return repos

    # ====================================================================
    #  Tier 3: 检测被删除的仓库
    # ====================================================================

    def _discover_deleted_repos(self) -> List[RepoTarget]:
        """检测已知仓库中哪些已被删除（返回 404）"""
        deleted = []
        now = time.time()
        to_check = []

        with self._known_repos_lock:
            # 只检查超过 1 小时前发现的仓库（太新的可能还没被删）
            for name, first_seen in self._known_repos.items():
                if now - first_seen > 3600:
                    to_check.append(name)

        # 只检查一小批（避免大量 404 请求被限流）
        for full_name in to_check[:20]:
            if self.stop_event.is_set():
                break
            try:
                url = f"https://github.com/{full_name}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                # 只发 HEAD 请求，不下载内容
                req.method = "HEAD"
                with urllib.request.urlopen(req, timeout=10):
                    # 还在，不动
                    pass
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    # 仓库已删除！但我们已经 clone 过了，看看扫没扫
                    with self._scanned_lock:
                        if full_name not in self._scanned_repos:
                            # 没扫过？那得抓紧，但 clone 可能已经失败了
                            logger.info(f"[GitClone] Tier3 发现已删除仓库: {full_name}")
                            deleted.append(RepoTarget(
                                full_name=full_name,
                                clone_url=f"https://github.com/{full_name}.git",
                                html_url=f"https://github.com/{full_name}",
                                detected_by="deleted_repo",
                            ))
                            self._stats['repos_deleted_after_pull'] += 1
            except Exception:
                pass

            time.sleep(0.2)  # 温柔

        return deleted

    # ====================================================================
    #  Tier 4: Code Search 兜底
    # ====================================================================

    def _discover_from_code_search(self, tokens: List[str]) -> List[RepoTarget]:
        """传统 Code Search 搜索关键词，兜底补充"""
        repos = []
        seen_full_names = set()
        headers = self._make_headers(tokens)

        for keyword in SEARCH_KEYWORDS:
            if self.stop_event.is_set():
                break
            try:
                # 只搜仓库，不搜文件 —— 用 /search/repositories
                url = (
                    f"https://api.github.com/search/repositories"
                    f"?q={urllib.parse.quote(keyword)}"
                    f"&sort=stars&order=desc&per_page=50"
                )
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())

                for item in data.get("items", []):
                    full_name = item.get("full_name", "")
                    if full_name and full_name not in seen_full_names:
                        seen_full_names.add(full_name)
                        repos.append(RepoTarget(
                            full_name=full_name,
                            clone_url=f"https://github.com/{full_name}.git",
                            html_url=item.get("html_url", f"https://github.com/{full_name}"),
                            stars=item.get("stargazers_count", 0),
                            description=item.get("description", "") or "",
                            language=item.get("language", "") or "",
                            detected_by="code_search",
                        ))

                time.sleep(0.5)

            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429):
                    time.sleep(10)
            except Exception as exc:
                logger.debug(f"[GitClone] Tier4 异常: {exc}")

        self._stats['repos_from_code_search'] += len(repos)
        return repos

    # ====================================================================
    #  HTTP 工具
    # ====================================================================

    def _make_headers(self, tokens: List[str]) -> Dict[str, str]:
        """构造请求头（带 Token 轮询）"""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-Secret-Scanner/2.0",
        }
        if tokens:
            idx = self._token_idx % len(tokens)
            self._token_idx = idx + 1
            headers["Authorization"] = f"token {tokens[idx]}"
        return headers

    # ====================================================================
    #  扫描单个仓库（与之前一致）
    # ====================================================================

    def _scan_one_repo(self, repo: RepoTarget):
        """用 Git partial clone 扫描一个仓库"""
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

            self._stats['repos_cloned'] += 1

            git_size = self._estimate_git_dir(work_dir)
            if git_size is not None and git_size > MAX_GIT_DIR_MB:
                logger.info(f"[GitClone]   .git {git_size}MB，超过 {MAX_GIT_DIR_MB}MB 限制，跳过")
                self._stats['repos_skipped_too_large'] += 1
                shutil.rmtree(work_dir, ignore_errors=True)
                return

            target_files = self._list_target_files(work_dir)
            if not target_files:
                shutil.rmtree(work_dir, ignore_errors=True)
                return

            self._batch_scan_files(work_dir, target_files, repo)

        except Exception as exc:
            logger.debug(f"[GitClone]   扫描异常 {repo.full_name}: {exc}")
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _partial_clone(self, clone_url: str, target_dir: Path) -> bool:
        """执行 git partial clone（只拉树）"""
        try:
            start = time.time()
            result = subprocess.run(
                ["git", "clone",
                 "--filter=blob:none",
                 "--depth=1",
                 "--single-branch",
                 "--no-checkout",
                 "--quiet",
                 clone_url, str(target_dir)],
                capture_output=True, text=True, timeout=120,
            )
            elapsed = time.time() - start

            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "Repository not found" in stderr or "404" in stderr:
                    pass  # 可能是刚被删除，没关系
                elif "timeout" in stderr.lower():
                    pass
                return False

            logger.debug(f"[GitClone]   clone 完成 ({elapsed:.1f}s)")
            return True

        except subprocess.TimeoutExpired:
            return False
        except FileNotFoundError:
            logger.error("[GitClone] git 命令不可用")
            return False
        except Exception:
            return False

    def _estimate_git_dir(self, repo_dir: Path) -> Optional[int]:
        """估算 .git 目录大小 (MB)"""
        git_dir = repo_dir / ".git"
        if not git_dir.exists():
            return None
        try:
            total = sum(f.stat().st_size for f in git_dir.rglob("*") if f.is_file())
            return total // (1024 * 1024)
        except Exception:
            return None

    def _list_target_files(self, repo_dir: Path) -> List[str]:
        """列出仓库中目标文件路径"""
        target_files = []
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "ls-tree", "-r", "HEAD", "--name-only"],
                capture_output=True, text=True, timeout=30,
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
                if any(kw in fname for kw in TARGET_FILENAME_KEYWORDS):
                    target_files.append(file_path)
                    continue

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return target_files

    def _batch_scan_files(self, repo_dir: Path, file_paths: List[str], repo: RepoTarget):
        """批量提取文件内容并扫描密钥"""
        self._stats['files_scanned'] += len(file_paths)

        for i in range(0, len(file_paths), SHOW_BATCH_SIZE):
            if self.stop_event.is_set():
                break

            batch = file_paths[i:i + SHOW_BATCH_SIZE]
            contents = self._batch_get_contents(repo_dir, batch)

            for file_path, content in zip(batch, contents):
                if content is None:
                    continue

                skip, skip_reason = should_skip_file(file_path, len(content.encode("utf-8")))
                if skip:
                    continue

                source_url = f"{repo.html_url}/blob/main/{file_path}"
                for platform, pattern in self._key_patterns.items():
                    if self.stop_event.is_set():
                        return
                    for match in pattern.finditer(content):
                        key = match.group()
                        if is_test_key(key):
                            continue
                        start = max(0, match.start() - 100)
                        end = min(len(content), match.end() + 100)
                        context = content[start:end]
                        result = ScanResult(
                            platform=platform,
                            api_key=key,
                            base_url="",
                            source_url=source_url,
                            context=context,
                        )
                        self._put_result(result)

    def _batch_get_contents(self, repo_dir: Path, file_paths: List[str]) -> List[Optional[str]]:
        """逐个用 git show 提取文件内容"""
        if not file_paths:
            return []
        results = []
        for fp in file_paths:
            if self.stop_event.is_set():
                results.append(None)
                continue
            try:
                r = subprocess.run(
                    ["git", "-C", str(repo_dir), "show", f"HEAD:{fp}"],
                    capture_output=True, text=True, timeout=30,
                )
                if r.returncode == 0 and r.stdout:
                    results.append(r.stdout)
                else:
                    results.append(None)
            except Exception:
                results.append(None)
        return results

    def _put_result(self, result: ScanResult):
        """将扫描结果送入验证队列"""
        try:
            ok = self.result_queue.put_nowait(result)
            if ok is False:
                self.result_queue.put(result, timeout=5)
        except Exception:
            pass
        self._stats['keys_found'] += 1
        if self.dashboard:
            try:
                self.dashboard.update_stats(keys_found=1)
            except Exception:
                pass

    def _cleanup(self):
        """清理临时目录"""
        try:
            if str(self._clone_root).startswith(tempfile.gettempdir()) or \
               str(self._clone_root).startswith("/tmp"):
                shutil.rmtree(self._clone_root, ignore_errors=True)
        except Exception:
            pass


# ============================================================================
#                          启动函数
# ============================================================================

def start_git_clone_scanner(
    result_queue: queue.Queue,
    db: Database,
    stop_event: threading.Event,
    dashboard=None,
    clone_dir: Optional[str] = None,
) -> threading.Thread:
    """启动 Git 克隆扫描器线程"""
    scanner = GitCloneScanner(
        result_queue=result_queue,
        db=db,
        stop_event=stop_event,
        dashboard=dashboard,
        clone_dir=clone_dir,
    )
    thread = threading.Thread(
        target=scanner.run,
        name="GitCloneScanner",
        daemon=True,
    )
    thread.start()
    return thread
