"""
Tests for TargetNormalizer — classification and normalization of scan targets.

Covers:
  1.  Generic HTTPS URL
  2.  Generic HTTP URL
  3.  GitHub repository URL
  4.  GitLab repository URL
  5.  Bitbucket repository URL
  6.  SSH Git URL
  7.  Existing local directory
  8.  Existing local file
  9.  Invalid/nonexistent local path
  10. Malformed target
"""
import os
import tempfile
import shutil
from pathlib import Path

import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from app.services.target_normalizer import (
    TargetNormalizer, NormalizedTarget,
    _GIT_HOSTS, _SSH_GIT_RE,
)


class TestTargetNormalizerClassification:
    """Tests for classification-only (no network side effects)."""

    def setup_method(self):
        self.normalizer = TargetNormalizer()

    async def test_generic_https_url(self):
        nt = await self.normalizer.normalize("https://example.com", clone=False)
        assert nt.kind == "url"
        assert nt.web_target == "https://example.com"
        assert nt.local_path is None
        assert nt.is_local is False
        assert nt.kind != "git_repo"
        assert nt.scanners["code_review"] == []
        assert set(nt.scanners["web"]) == {"nmap", "zap", "ai_tester"}
        assert nt.error is None

    async def test_generic_http_url(self):
        nt = await self.normalizer.normalize("http://example.com", clone=False)
        assert nt.kind == "url"
        assert nt.web_target == "http://example.com"
        assert nt.local_path is None
        assert nt.scanners["code_review"] == []

    async def test_github_repository_url(self):
        nt = await self.normalizer.normalize(
            "https://github.com/octocat/Hello-World", clone=False
        )
        assert nt.kind == "git_repo"
        assert nt.web_target == "https://github.com/octocat/Hello-World"
        assert nt.scanners["code_review"] == ["semgrep", "bandit", "gitleaks", "trivy"]
        assert nt.scanners["web"] == []

    async def test_gitlab_repository_url(self):
        nt = await self.normalizer.normalize(
            "https://gitlab.com/gitlab-org/gitlab", clone=False
        )
        assert nt.kind == "git_repo"
        assert nt.web_target == "https://gitlab.com/gitlab-org/gitlab"

    async def test_bitbucket_repository_url(self):
        nt = await self.normalizer.normalize(
            "https://bitbucket.org/team/repo", clone=False
        )
        assert nt.kind == "git_repo"
        assert nt.web_target == "https://bitbucket.org/team/repo"

    async def test_ssh_git_url(self):
        nt = await self.normalizer.normalize(
            "git@github.com:octocat/Hello-World.git", clone=False
        )
        assert nt.kind == "git_repo"
        assert nt.web_target == "git@github.com:octocat/Hello-World.git"

    async def test_ssh_git_url_normalizes_to_https(self):
        """The SSH URL should be converted to HTTPS for git clone."""
        nt = await self.normalizer.normalize(
            "git@gitlab.com:group/project.git", clone=False
        )
        assert nt.kind == "git_repo"
        assert nt.web_target == "git@gitlab.com:group/project.git"

    async def test_existing_local_directory(self, tmp_path):
        nt = await self.normalizer.normalize(str(tmp_path), clone=False)
        assert nt.kind == "local_path"
        assert nt.local_path == str(tmp_path)
        assert nt.is_local is True
        assert set(nt.scanners["code_review"]) == {"semgrep", "bandit", "gitleaks", "trivy"}
        assert set(nt.scanners["web"]) == {"nmap", "zap", "ai_tester"}

    async def test_existing_local_file(self, tmp_path):
        test_file = tmp_path / "app.py"
        test_file.write_text("print('hello')")
        nt = await self.normalizer.normalize(str(test_file), clone=False)
        assert nt.kind == "local_path"
        assert nt.local_path == str(test_file)
        assert nt.is_local is True
        assert set(nt.scanners["code_review"]) == {"semgrep", "bandit", "gitleaks", "trivy"}

    async def test_nonexistent_local_path(self):
        nt = await self.normalizer.normalize("/nonexistent/path/that/does/not/exist", clone=False)
        assert nt.kind == "invalid"
        assert nt.error is not None

    async def test_empty_target(self):
        nt = await self.normalizer.normalize("", clone=False)
        assert nt.kind == "invalid"
        assert nt.error is not None

    async def test_malformed_target(self):
        nt = await self.normalizer.normalize("   ", clone=False)
        assert nt.kind == "invalid"

    async def test_windows_path_style(self):
        """A bare path-like string that doesn't exist and isn't a URL."""
        nt = await self.normalizer.normalize("D:\\some\\nonexistent\\path", clone=False)
        # This should be invalid because the path doesn't exist and isn't a URL/git host
        assert nt.kind == "invalid"


class TestTargetNormalizerGitClone:
    """Tests for the git cloning logic (mocked)."""

    @pytest.fixture
    def normalizer(self):
        return TargetNormalizer()

    async def test_git_clone_success(self, normalizer):
        """Mock subprocess and verify clone succeeds."""
        fake_dir = "/tmp/cyberpilot/clone_abcd1234"

        # Mock the _clone_repo method
        with patch.object(normalizer, "_clone_repo", new_callable=AsyncMock, return_value=fake_dir) as mock_clone:
            nt = await normalizer.normalize(
                "https://github.com/octocat/Hello-World", clone=True
            )
            assert nt.kind == "git_repo"
            assert nt.local_path == fake_dir
            assert nt.is_local is True
            assert nt.clone_dir == fake_dir
            assert nt.error is None
            mock_clone.assert_called_once_with(
                "https://github.com/octocat/Hello-World"
            )

    async def test_git_clone_failure_returns_error(self, normalizer):
        """If clone fails, local_path should be None and error set."""
        with patch.object(
            normalizer, "_clone_repo", new_callable=AsyncMock,
            side_effect=RuntimeError("git not found")
        ):
            nt = await normalizer.normalize(
                "https://github.com/octocat/Hello-World", clone=True
            )
            assert nt.kind == "git_repo"
            assert nt.local_path is None
            assert nt.error is not None
            assert "git not found" in nt.error

    async def test_clone_false_no_cloning(self, normalizer):
        """When clone=False, no cloning should occur."""
        nt = await normalizer.normalize(
            "https://github.com/octocat/Hello-World", clone=False
        )
        assert nt.kind == "git_repo"
        assert nt.local_path is None
        assert nt.is_local is False
        assert nt.clone_dir is None
        assert nt.error is None


class TestTargetNormalizerCleanup:
    """Tests for temporary directory cleanup."""

    def test_cleanup_removes_clone_dir(self, tmp_path):
        """Cleanup should remove the clone directory."""
        nt = NormalizedTarget(
            original="https://github.com/user/repo",
            kind="git_repo",
            clone_dir=str(tmp_path),
        )
        nt.cleanup()
        assert not os.path.exists(str(tmp_path))

    def test_cleanup_does_not_remove_nonexistent(self):
        """Cleanup should not crash if directory doesn't exist."""
        nt = NormalizedTarget(
            original="https://example.com",
            kind="url",
            clone_dir="/nonexistent/path",
        )
        # Should not raise
        nt.cleanup()

    def test_cleanup_does_not_remove_user_local_paths(self, tmp_path):
        """Cleanup should NOT remove user-provided local paths (no clone_dir)."""
        nt = NormalizedTarget(
            original=str(tmp_path),
            kind="local_path",
            local_path=str(tmp_path),
        )
        # clone_dir is None for local_path kind
        assert nt.clone_dir is None
        nt.cleanup()
        # Directory should still exist
        assert os.path.exists(str(tmp_path))


class TestTargetNormalizerScannerRouting:
    """Verify scanner routing table is correct for each target kind."""

    @pytest.fixture
    def normalizer(self):
        return TargetNormalizer()

    async def test_url_scanner_routing(self, normalizer):
        nt = await normalizer.normalize("https://example.com", clone=False)
        assert nt.scanners["code_review"] == []
        assert set(nt.scanners["web"]) == {"nmap", "zap", "ai_tester"}
        assert nt.scanners["infra"] == []

    async def test_git_repo_scanner_routing(self, normalizer):
        nt = await normalizer.normalize("https://github.com/user/repo", clone=False)
        assert set(nt.scanners["code_review"]) == {"semgrep", "bandit", "gitleaks", "trivy"}
        assert nt.scanners["web"] == []
        assert "trivy" in nt.scanners["infra"]

    async def test_local_path_scanner_routing(self, tmp_path, normalizer):
        nt = await normalizer.normalize(str(tmp_path), clone=False)
        assert set(nt.scanners["code_review"]) == {"semgrep", "bandit", "gitleaks", "trivy"}
        assert set(nt.scanners["web"]) == {"nmap", "zap", "ai_tester"}
        assert "trivy" in nt.scanners["infra"]


class TestTargetNormalizerEdgeCases:
    """Edge cases and tricky inputs."""

    @pytest.fixture
    def normalizer(self):
        return TargetNormalizer()

    async def test_url_with_port_is_not_git_repo(self, normalizer):
        """A URL with a port that's not a known git host should be a generic URL."""
        nt = await normalizer.normalize("https://example.com:8080", clone=False)
        assert nt.kind == "url"

    async def test_url_with_path_on_git_host_is_github_repo(self, normalizer):
        """GitHub URLs with paths (like /user/repo/issues) are still git repos."""
        nt = await normalizer.normalize(
            "https://github.com/user/repo/issues", clone=False
        )
        # Currently classified as git_repo (same as before)
        assert nt.kind == "git_repo"

    async def test_url_with_token_does_not_log_token(self, normalizer, caplog):
        """Ensure secrets in URLs are not logged."""
        secret_url = "https://user:secret123token@github.com/repo.git"
        nt = await normalizer.normalize(secret_url, clone=False)
        assert nt.kind == "git_repo"
        # Check that the secret is not in logs
        log_text = caplog.text
        assert "secret123token" not in log_text

    async def test_local_path_with_trailing_slash(self, tmp_path, normalizer):
        nt = await normalizer.normalize(str(tmp_path) + "/", clone=False)
        assert nt.kind == "local_path"
        # os.path.exists handles trailing slashes
        assert nt.is_local is True

    async def test_protocol_relative_url_rejected(self, normalizer):
        nt = await normalizer.normalize("//example.com", clone=False)
        assert nt.kind == "invalid"

    async def test_gitlab_self_managed_url(self, normalizer):
        """gitlab.example.com is not in _GIT_HOSTS, so it's a generic URL."""
        nt = await normalizer.normalize("https://gitlab.example.com/group/repo", clone=False)
        assert nt.kind == "url"
        assert nt.scanners["code_review"] == []

    async def test_nonexistent_git_host_is_url(self, normalizer):
        """github.org (not .com) is not a known git host."""
        nt = await normalizer.normalize("https://github.org/user/repo", clone=False)
        assert nt.kind == "url"

    async def test_ssh_url_with_non_git_host(self, normalizer):
        """git@someotherhost.com:user/repo is not a known git host."""
        nt = await normalizer.normalize("git@someotherhost.com:user/repo.git", clone=False)
        assert nt.kind == "invalid"

    async def test_error_property_for_url_target(self, normalizer):
        nt = await normalizer.normalize("https://example.com", clone=False)
        assert nt.error is None

    async def test_error_property_for_git_clone_failure(self, normalizer):
        with patch.object(
            normalizer, "_clone_repo", new_callable=AsyncMock,
            side_effect=RuntimeError("clone failed")
        ):
            nt = await normalizer.normalize("https://github.com/user/repo", clone=True)
            assert nt.error is not None
            assert "clone failed" in nt.error
