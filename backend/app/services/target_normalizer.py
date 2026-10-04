"""
Target Normalization Layer for CyberPilot.

Classifies scan targets into one of four kinds and produces the
appropriate local/web representations for routing to the correct scanners.

Target kinds:
  - "url"        : generic web URL (e.g. https://example.com)
  - "git_repo"   : Git hosting URL (e.g. https://github.com/user/repo)
                  Cloned to a temp directory.
  - "local_path" : existing local directory or file
  - "invalid"    : malformed or unsupported target

The normalizer is intentionally side-effect-free for URL and local_path
kinds.  Git-repo cloning is performed only when explicitly requested via
``normalize()`` with ``clone=True`` (the default), and the clone is
cleaned up when ``cleanup()`` is called.
"""
import asyncio
import logging
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Git-hosting domains that indicate a repository URL.
_GIT_HOSTS = {
    "github.com", "gitlab.com", "bitbucket.org", "codeberg.org",
    "sourceforge.net",
}

# SSH git URL pattern: git@github.com:user/repo.git  or  git@gitlab.com:user/repo
_SSH_GIT_RE = re.compile(
    r"^git@([^:]+):(.+)$"
)

# Scanner groups — ordered lists so results are deterministic.
_CODE_SCANNERS = ["semgrep", "bandit", "gitleaks", "trivy"]
_WEB_SCANNERS = ["nmap", "zap", "ai_tester"]


@dataclass
class NormalizedTarget:
    """Result of normalizing a raw target string."""

    original: str
    kind: str                      # "url" | "git_repo" | "local_path" | "invalid"
    web_target: Optional[str] = None
    local_path: Optional[str] = None
    is_local: bool = False
    clone_dir: Optional[str] = None
    clone_attempted: bool = False
    clone_error: Optional[str] = None
    scanners: Dict[str, List[str]] = field(default_factory=dict)
    # scanners keys: "code_review" / "web" / "infra" / "all"

    @property
    def error(self) -> Optional[str]:
        """Human-readable error if normalization failed."""
        if self.kind == "invalid":
            return self.clone_error or "Target could not be classified."
        # Only report a clone error if we actually attempted cloning
        if self.kind == "git_repo" and self.clone_attempted and self.clone_dir is None:
            return self.clone_error or "Repository could not be cloned."
        return None

    def cleanup(self) -> None:
        """Remove temporary clone directory if one was created by us."""
        if self.clone_dir and os.path.isdir(self.clone_dir):
            try:
                # Only remove if it's under /tmp or a known temp location
                real_path = os.path.realpath(self.clone_dir)
                parent = os.path.realpath(tempfile.gettempdir())
                if real_path.startswith(parent):
                    shutil.rmtree(real_path, ignore_errors=True)
                    logger.info("Cleaned up temporary clone: %s", real_path)
            except Exception as e:
                logger.warning("Failed to clean up clone dir %s: %s", self.clone_dir, e)
            self.clone_dir = None


class TargetNormalizer:
    """
    Classifies and normalizes scan targets.

    Usage::

        nr = TargetNormalizer()
        nt = await nr.normalize("https://github.com/user/repo")
        # nt.local_path  -> "/tmp/cyberpilot/clone_xxxx"
        # nt.web_target  -> "https://github.com/user/repo"
        code_scanner_target = nt.local_path   # for semgrep, bandit, etc.
        web_scanner_target = nt.web_target    # for nmap, zap, etc.
        ...
        nt.cleanup()
    """

    def __init__(self, clone_timeout: int = 120):
        self._clone_timeout = clone_timeout

    # ── Classification helpers ──────────────────────────────────────────────

    @staticmethod
    def _is_git_host(host: str) -> bool:
        return host.lower() in _GIT_HOSTS

    @staticmethod
    def _is_ssh_git_url(target: str) -> bool:
        return _SSH_GIT_RE.match(target) is not None

    @staticmethod
    def _looks_like_url(target: str) -> bool:
        return target.lower().startswith(("http://", "https://"))

    @staticmethod
    def _is_local_path(target: str) -> bool:
        """True if target is a path that exists on the local filesystem."""
        return os.path.exists(target)

    # ── Public API ──────────────────────────────────────────────────────────

    async def normalize(self, target: str, clone: bool = True) -> NormalizedTarget:
        """
        Classify *target* and produce a :class:`NormalizedTarget`.

        When *clone* is ``True`` (default) and the target is a git
        repository URL, the repository is cloned into a unique temporary
        directory and ``local_path`` points to the clone.

        Set *clone* to ``False`` for classification-only mode (no network
        side effects).
        """
        target = target.strip()

        if not target:
            return NormalizedTarget(
                original=target,
                kind="invalid",
                clone_error="Empty target string.",
                scanners={"code_review": [], "web": [], "infra": []},
            )

        # ── 1. Existing local path (directory or file) ──
        if self._is_local_path(target):
            return self._build_local_result(target)

        # ── 2. Git repository URL (https or ssh) ──
        git_info = self._try_classify_git_url(target)
        if git_info is not None:
            kind, normalized_url = git_info
            return await self._build_repo_result(target, normalized_url, clone)

        # ── 3. Generic web URL ──
        if self._looks_like_url(target):
            return self._build_url_result(target)

        # ── 4. Invalid ──
        return NormalizedTarget(
            original=target,
            kind="invalid",
            clone_error=f"Unrecognized target format: {target[:120]!r}",
            scanners={"code_review": [], "web": [], "infra": []},
        )

    # ── Builders ───────────────────────────────────────────────────────────

    def _build_local_result(self, path: str) -> NormalizedTarget:
        """Build result for an existing local directory or file."""
        return NormalizedTarget(
            original=path,
            kind="local_path",
            local_path=path,
            is_local=True,
            web_target=None,
            scanners={
                "code_review": list(_CODE_SCANNERS),
                "web": list(_WEB_SCANNERS),
                "infra": ["trivy"],
                "all": ["nmap", "semgrep", "bandit", "gitleaks", "trivy"],
            },
        )

    def _build_url_result(self, url: str) -> NormalizedTarget:
        """Build result for a generic (non-git) web URL."""
        return NormalizedTarget(
            original=url,
            kind="url",
            web_target=url,
            local_path=None,
            is_local=False,
            scanners={
                "code_review": [],
                "web": list(_WEB_SCANNERS),
                "infra": [],
                "all": ["nmap", "zap", "ai_tester"],
            },
        )

    async def _build_repo_result(
        self,
        original: str,
        clone_url: str,
        clone: bool,
    ) -> NormalizedTarget:
        """Build result for a git repository — optionally clone it."""
        result = NormalizedTarget(
            original=original,
            kind="git_repo",
            web_target=original,
            scanners={
                "code_review": list(_CODE_SCANNERS),
                "web": [],
                "infra": ["trivy"],
                "all": ["semgrep", "bandit", "gitleaks", "trivy"],
            },
        )

        if not clone:
            return result

        result.clone_attempted = True

        # Clone to a unique temp directory
        try:
            clone_dir = await self._clone_repo(clone_url)
            result.local_path = clone_dir
            result.is_local = True
            result.clone_dir = clone_dir
            logger.info(
                "Target type: git_repo. Repository cloned to %s. "
                "Code scanners: Semgrep, Bandit, Gitleaks, Trivy.",
                clone_dir,
            )
        except Exception as e:
            result.clone_error = str(e)
            result.local_path = None
            result.is_local = False
            logger.warning("Failed to clone repository %s: %s", clone_url, e)

        return result

    # ── Git URL detection ────────────────────────────────────────────────

    @staticmethod
    def _try_classify_git_url(target: str) -> Optional[tuple]:
        """
        Return (kind, normalized_clone_url) if *target* is a git repo URL,
        otherwise ``None``.

        ``kind`` is always "git_repo" but kept as a tuple for future
        extensibility (e.g. distinguishing GitHub Enterprise).
        """
        # SSH: git@github.com:user/repo.git
        if target.startswith("git@"):
            m = _SSH_GIT_RE.match(target)
            if m:
                host = m.group(1)
                path = m.group(2)
                if TargetNormalizer._is_git_host(host):
                    https_url = f"https://{host}/{path}"
                    return ("git_repo", https_url)
            return None  # SSH but not a known git host — not a repo

        # HTTPS URLs — handle userinfo (user:pass@host) by stripping it
        if target.lower().startswith(("http://", "https://")):
            parsed = urlparse(target)
            # urlparse puts userinfo@ into netloc; extract just the host
            netloc = parsed.hostname or ""
            if not netloc:
                # Fallback: strip userinfo manually
                netloc = parsed.netloc
                if "@" in netloc:
                    netloc = netloc.rsplit("@", 1)[-1]
                netloc = netloc.split(":")[0]

            if TargetNormalizer._is_git_host(netloc):
                return ("git_repo", target)

        return None

    # ── Git cloning ───────────────────────────────────────────────────────

    async def _clone_repo(self, url: str) -> str:
        """
        Clone *url* into a unique temp directory and return the directory path.

        Uses ``git clone`` with argument lists (no shell=True), a timeout,
        and ``--depth 1`` for speed.
        """
        clone_id = uuid.uuid4().hex[:8]
        base_tmp = os.path.join(tempfile.gettempdir(), "cyberpilot")
        os.makedirs(base_tmp, exist_ok=True)

        clone_dir = os.path.join(base_tmp, f"clone_{clone_id}")

        # Ensure the directory does not already exist (avoid overwriting)
        if os.path.exists(clone_dir):
            clone_dir = os.path.join(
                base_tmp, f"clone_{clone_id}_{uuid.uuid4().hex[:4]}"
            )

        # Build the git command as an argument list — no shell=True
        args = [
            "git", "clone",
            "--depth", "1",
            "--no-tags",
            url,
            clone_dir,
        ]

        # Log without credentials: split on @ and take the host part
        safe_url = url.split("@")[-1] if "@" in url else url
        logger.info("Cloning repository: %s -> %s", safe_url, clone_dir)

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self._clone_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                raise TimeoutError(
                    f"Git clone timed out after {self._clone_timeout}s"
                )

            if proc.returncode != 0:
                # Clean up partial clone
                if os.path.isdir(clone_dir):
                    shutil.rmtree(clone_dir, ignore_errors=True)
                stderr_text = stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"git clone failed (exit {proc.returncode}): {stderr_text[:500]}"
                )

            logger.info("Repository cloned successfully to %s", clone_dir)
            return clone_dir

        except FileNotFoundError:
            raise RuntimeError(
                "git binary not found — cannot clone repository. "
                "Install git or provide a local path target instead."
            )
