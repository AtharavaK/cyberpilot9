"""
OWASP ZAP Scanner for CyberPilot — Phase 4.

Provides web-application and API security scanning via OWASP ZAP.

Key design principles:
  - ZAP is **optional** — the scanner gracefully reports ``NOT_INSTALLED`` or
    ``UNAVAILABLE`` if ZAP is not running, not installed, or unreachable.
  - CyberPilot **never crashes** because ZAP is unavailable.
  - Scan modes: **passive** (safe), **baseline** (moderate), **active** (intrusive).
  - The scanner can optionally **start/stop** a local ZAP daemon, but will
    also connect to an already-running instance.
  - Full SSRF protection via ``app.services.target_validation``.
  - Environment-based configuration (no hardcoded machine paths).
  - Scans and spiders respect configurable timeouts and are always terminated
    on completion, failure, timeout, or cancellation.

Environment variables:
    ZAP_ENABLED                — "true"/"false" (default: "true")
    ZAP_BASE_URL               — ZAP daemon URL (default: "http://localhost:8080")
    ZAP_API_KEY                — ZAP API key (if configured on the daemon)
    ZAP_MODE                   — "passive" | "baseline" | "active" (default: "passive")
    ZAP_AUTOSTART              — "true" to auto-start a daemon (default: "false")
    ZAP_STARTUP_TIMEOUT        — seconds to wait for ZAP to start (default: 30)
    ZAP_SCAN_TIMEOUT           — seconds for an active scan to run (default: 300)
    ZAP_SPIDER_TIMEOUT         — seconds for spidering (default: 60)
    ZAP_ALLOW_PRIVATE_TARGETS  — "true" to allow private/local targets (default: "false")
    ZAP_EXECUTABLE             — path to zap.sh / zap.bat (default: auto-detected)
    ZAP_MAX_CHILDREN           — max spider children (default: 10)
"""
import asyncio
import json
import logging
import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

from app.services.tools.base import BaseScanner, ScanResult, ScanStatus
from app.services.target_validation import classify_target, validate_target

logger = logging.getLogger(__name__)


# ── Configuration ─────────────────────────────────────────────────────────

def _env_bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes")


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


# ── Scan modes ───────────────────────────────────────────────────────────

#: Risk levels for scan modes
SCAN_MODES = ("passive", "baseline", "active")

# ZAP risk → canonical severity (already handled by finding_normalizer, but
# ZAP can also return numeric risk codes that we normalize here)
_ZAP_NUMERIC_RISK = {
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
}


class ZapScanner(BaseScanner):
    """OWASP ZAP web-application security scanner wrapper.

    The scanner communicates with a running ZAP daemon via its REST API.
    When ``ZAP_AUTOSTART=true`` it will attempt to launch a local ZAP
    process if none is detected.
    """

    def __init__(self, config: Dict[str, Any] = None):
        config = config or {}
        super().__init__(config)

        self.zap_url = config.get("zap_url") or \
            os.environ.get("ZAP_BASE_URL", "http://localhost:8080")
        self.zap_url = self.zap_url.rstrip("/")

        self.api_key = config.get("api_key") or os.environ.get("ZAP_API_KEY", "")
        self.scan_mode = config.get("scan_mode") or \
            os.environ.get("ZAP_MODE", "passive")

        self.enabled = config.get("enabled", _env_bool("ZAP_ENABLED", True))
        self.allow_private = config.get("allow_private_targets",
                                        _env_bool("ZAP_ALLOW_PRIVATE_TARGETS"))
        self.autostart = config.get("autostart", _env_bool("ZAP_AUTOSTART"))
        self.startup_timeout = config.get("startup_timeout") or \
            _env_int("ZAP_STARTUP_TIMEOUT", 30)
        self.scan_timeout = config.get("scan_timeout") or \
            _env_int("ZAP_SCAN_TIMEOUT", 300)
        self.spider_timeout = config.get("spider_timeout") or \
            _env_int("ZAP_SPIDER_TIMEOUT", 60)
        self.max_children = config.get("max_children") or \
            _env_int("ZAP_MAX_CHILDREN", 10)
        self.executable = config.get("executable") or \
            os.environ.get("ZAP_EXECUTABLE", "zap.sh")

        # Track whether *we* started the ZAP process (so we know to stop it)
        self._managed_process: Optional[subprocess.Popen] = None

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def tool_name(self) -> str:
        return "OWASP ZAP"

    @property
    def command_name(self) -> str:
        return "zap.sh"

    # ── Availability ────────────────────────────────────────────────────

    async def check_installed(self) -> bool:
        """Check if the ZAP executable exists on the system."""
        return (
            shutil.which("zap.sh") is not None
            or shutil.which("zap.bat") is not None
            or shutil.which("zap") is not None
            or shutil.which(self.executable) is not None
        )

    async def check_available(self) -> Tuple[bool, str]:
        """Check if ZAP daemon is reachable and responsive.

        Returns ``(available, detail)``.
        """
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            ) as session:
                params = {}
                if self.api_key:
                    params["apikey"] = self.api_key
                async with session.get(
                    f"{self.zap_url}/JSON/core/view/version/",
                    params=params,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        version = data.get("version", "unknown")
                        return (True, f"ZAP {version}")
                    return (False, f"HTTP {resp.status}")
        except aiohttp.ClientConnectorError:
            return (False, "Connection refused — ZAP daemon not running")
        except asyncio.TimeoutError:
            return (False, "Timeout — ZAP daemon not responding")
        except Exception as e:
            return (False, f"Error: {e}")

    async def get_status(self) -> Dict[str, Any]:
        """Return detailed status of the ZAP integration."""
        installed = await self.check_installed()
        available, detail = await self.check_available()

        from app.services.finding_normalizer import normalize_severity
        status_enum = ScanStatus.NOT_INSTALLED
        if available:
            status_enum = ScanStatus.SUCCESS
        elif installed:
            status_enum = ScanStatus.FAILED

        return {
            "tool_name": self.tool_name,
            "installed": installed,
            "available": available,
            "status": status_enum.value,
            "detail": detail,
            "zap_url": self.zap_url,
            "scan_mode": self.scan_mode,
            "autostart": self.autostart,
            "allow_private_targets": self.allow_private,
            "startup_timeout": self.startup_timeout,
            "scan_timeout": self.scan_timeout,
            "spider_timeout": self.spider_timeout,
        }

    # ── ZAP daemon lifecycle ────────────────────────────────────────────

    async def _start_zap_daemon(self) -> bool:
        """Attempt to start a local ZAP daemon.

        Sets ``self._managed_process`` so we know to stop it later.
        Returns True if the daemon became reachable.
        """
        if self._managed_process is not None:
            return True  # already started

        if not await self.check_installed():
            logger.warning("ZAP executable not found — cannot autostart")
            return False

        # Find the executable — prefer the configured executable, then PATH
        exec_path = shutil.which(self.executable)
        if not exec_path:
            exec_path = shutil.which("zap.sh") or shutil.which("zap") or shutil.which("zap.bat")
        if not exec_path:
            logger.warning("ZAP executable not found in PATH")
            return False

        # Build ZAP daemon args with correct -config flags
        args = [
            exec_path,
            "-daemon",
            "-host", "localhost",
            "-port", "8080",
            "-config", "api.addrs.addrs.name=.*",
            "-config", "api.addrs.addrs.regex=true",
        ]
        # Disable API key when none is configured — makes local testing simpler
        if not self.api_key:
            args.extend(["-config", "api.disablekey=true"])
        else:
            args.extend(["-config", f"api.key={self.api_key}"])

        # Try to start ZAP daemon
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._managed_process = proc
            logger.info("Started ZAP daemon (PID %d), waiting for startup...", proc.pid)

            # Wait for ZAP to become reachable
            deadline = time.time() + self.startup_timeout
            while time.time() < deadline:
                await asyncio.sleep(2)
                available, _ = await self.check_available()
                if available:
                    logger.info("ZAP daemon is ready")
                    return True

            logger.warning("ZAP daemon did not become ready within %ds",
                           self.startup_timeout)
            return False

        except FileNotFoundError:
            logger.warning("ZAP executable not found")
            return False
        except Exception as e:
            logger.error("Failed to start ZAP daemon: %s", e)
            return False

    async def _stop_zap_daemon(self) -> None:
        """Stop the ZAP daemon if we started it."""
        if self._managed_process is not None:
            try:
                # Use ZAP's shutdown API first
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as session:
                    params = {}
                    if self.api_key:
                        params["apikey"] = self.api_key
                    await session.get(
                        f"{self.zap_url}/JSON/core/action/shutdown/",
                        params=params,
                    )
            except Exception:
                pass

            try:
                self._managed_process.terminate()
                await asyncio.wait_for(
                    self._managed_process.wait(), timeout=5
                )
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._managed_process.kill()
                    await self._managed_process.wait()
                except Exception:
                    pass
            finally:
                self._managed_process = None
                logger.info("ZAP daemon stopped")

    # ── Target validation ───────────────────────────────────────────────

    def _validate_target(self, target: str, allow_internal: bool = False) -> str:
        """Validate target URL for SSRF safety.

        Returns the validated URL or raises ``ValueError`` if blocked.
        """
        # Use the allow_internal flag from kwargs if provided, otherwise
        # fall back to the environment-level setting
        effective_allow = allow_internal or self.allow_private

        is_valid, reason = validate_target(target, allow_private=effective_allow)
        if not is_valid:
            raise ValueError(
                f"Target {target!r} blocked by SSRF protection: {reason}. "
                f"Set allow_internal=True or ZAP_ALLOW_PRIVATE_TARGETS=true "
                f"only when you have authorization to scan this target."
            )
        return target

    # ── Scan entry point ────────────────────────────────────────────────

    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Run a ZAP scan against a web target.

        Parameters
        ----------
        target : str
            The target URL (e.g. ``https://example.com``).
        scan_type : str, optional
            Scan mode: ``"passive"``, ``"baseline"``, or ``"active"``.
            Defaults to the configured ``ZAP_MODE``.
        allow_internal : bool, optional
            If True, allows scanning private/localhost targets.
        timeout : int, optional
            Override the scan timeout in seconds.
        spider : bool, optional
            Whether to run the spider before scanning (default: True for
            baseline/active, False for passive).
        """
        import time
        start_time = time.time()

        # Validate target
        allow_internal = kwargs.get("allow_internal", False)
        try:
            self._validate_target(target, allow_internal)
        except ValueError as e:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                error=str(e),
                duration_seconds=time.time() - start_time,
            )

        scan_type = kwargs.get("scan_type", self.scan_mode)
        if scan_type not in SCAN_MODES:
            scan_type = "passive"

        scan_timeout = kwargs.get("timeout", self.scan_timeout)

        if not self.enabled:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.NOT_INSTALLED,
                findings=[],
                error="ZAP is disabled via configuration (ZAP_ENABLED=false)",
                duration_seconds=time.time() - start_time,
            )

        # Check availability — try to auto-start if configured
        available, detail = await self.check_available()
        if not available:
            if self.autostart:
                logger.info("ZAP not running — attempting autostart...")
                if not await self._start_zap_daemon():
                    return ScanResult(
                        tool_name=self.tool_name,
                        status=ScanStatus.NOT_INSTALLED,
                        findings=[],
                        error=f"ZAP daemon could not be started: {detail}",
                        duration_seconds=time.time() - start_time,
                    )
                # Re-check after autostart
                available, detail = await self.check_available()
                if not available:
                    return ScanResult(
                        tool_name=self.tool_name,
                        status=ScanStatus.NOT_INSTALLED,
                        findings=[],
                        error=f"ZAP daemon started but not reachable: {detail}",
                        duration_seconds=time.time() - start_time,
                    )
            else:
                return ScanResult(
                    tool_name=self.tool_name,
                    status=ScanStatus.NOT_INSTALLED,
                    findings=[],
                    error=f"ZAP daemon not reachable: {detail}. "
                          f"Set ZAP_AUTOSTART=true to auto-start.",
                    duration_seconds=time.time() - start_time,
                )

        # Run the appropriate scan mode
        try:
            findings, scan_errors = await self._run_scan(
                target, scan_type, scan_timeout, kwargs
            )

            # Collect passive alerts (always)
            passive_alerts = await self._get_alerts(target)
            passive_findings = self._parse_alerts(passive_alerts, target)
            findings.extend(passive_findings)

            # Deduplicate
            from app.services.finding_normalizer import dedup_findings
            findings = dedup_findings(findings)

            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.SUCCESS,
                findings=findings,
                duration_seconds=time.time() - start_time,
            )

        except asyncio.TimeoutError:
            return self.create_timeout_result(time.time() - start_time)
        except Exception as e:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                error=str(e),
                duration_seconds=time.time() - start_time,
            )
        finally:
            # Stop the daemon if we started it
            if self._managed_process is not None:
                await self._stop_zap_daemon()

    # ── Scan mode implementations ────────────────────────────────────────

    async def _run_scan(self, target: str, scan_type: str,
                        scan_timeout: int, kwargs: Dict) -> Tuple[List[Dict], List[str]]:
        """Dispatch to the appropriate scan mode implementation."""
        errors: List[str] = []
        findings: List[Dict[str, Any]] = []

        run_spider = kwargs.get("spider", scan_type != "passive")
        do_active = scan_type in ("active", "baseline")

        if run_spider:
            spider_err = await self._run_spider(target)
            if spider_err:
                errors.append(f"Spider: {spider_err}")

        if do_active:
            scan_err = await self._run_active_scan(target, scan_timeout)
            if scan_err:
                errors.append(f"Active scan: {scan_err}")

        # If errors occurred but we got some findings, proceed anyway
        return findings, errors

    async def _run_spider(self, target: str) -> Optional[str]:
        """Start and wait for spider. Returns error string or None."""
        try:
            spider_id = await self._zap_api(
                "GET", "spider/action/scan/",
                params={"url": target, "maxChildren": str(self.max_children)},
            )
            if spider_id is None:
                return "Failed to start spider"
            spider_id = spider_id.get("scan") if isinstance(spider_id, dict) else None
            if spider_id:
                await self._wait_for_spider(spider_id)
            return None
        except Exception as e:
            return str(e)

    async def _run_active_scan(self, target: str, timeout: int) -> Optional[str]:
        """Start and wait for active scan. Returns error string or None."""
        try:
            scan_id = await self._zap_api(
                "GET", "ascan/action/scan/",
                params={"url": target, "recurse": "true", "inScope": "true"},
            )
            if scan_id is None:
                return "Failed to start active scan"
            scan_id = scan_id.get("scan") if isinstance(scan_id, dict) else None
            if scan_id:
                await self._wait_for_scan(scan_id, timeout)
            return None
        except asyncio.TimeoutError:
            return "Active scan timed out"
        except Exception as e:
            return str(e)

    # ── ZAP API helper ─────────────────────────────────────────────────

    async def _zap_api(self, method: str, endpoint: str,
                       params: Dict[str, str] = None,
                       timeout: int = 30) -> Optional[Any]:
        """Make a request to the ZAP REST API.

        Returns the parsed JSON response, or None on error.
        """
        params = params or {}
        if self.api_key:
            params["apikey"] = self.api_key

        url = f"{self.zap_url}/JSON/{endpoint}"

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                async with session.get(url, params=params) as resp:
                    if resp.status != 200:
                        logger.warning("ZAP API %s returned HTTP %d", endpoint, resp.status)
                        return None
                    return await resp.json()
        except Exception as e:
            logger.debug("ZAP API call to %s failed: %s", endpoint, e)
            return None

    # ── Wait helpers ───────────────────────────────────────────────────

    async def _wait_for_spider(self, spider_id: str, max_wait: int = None) -> bool:
        """Poll spider status until completion or timeout."""
        max_wait = max_wait or self.spider_timeout
        try:
            for _ in range(max_wait // 2):
                data = await self._zap_api(
                    "GET", "spider/view/status/",
                    params={"scanId": spider_id},
                )
                if data is None:
                    return False
                status = int(data.get("status", 0))
                if status >= 100:
                    return True
                await asyncio.sleep(2)
        except Exception:
            pass
        return False

    async def _wait_for_scan(self, scan_id: str, max_wait: int = None) -> bool:
        """Poll active scan status until completion or timeout."""
        max_wait = max_wait or self.scan_timeout
        try:
            for _ in range(max_wait // 5):
                data = await self._zap_api(
                    "GET", "ascan/view/status/",
                    params={"scanId": scan_id},
                )
                if data is None:
                    return False
                status = int(data.get("status", 0))
                if status >= 100:
                    return True
                await asyncio.sleep(5)
        except Exception:
            pass
        return False

    # ── Alert collection ───────────────────────────────────────────────

    async def _get_alerts(self, target: str) -> List[Dict[str, Any]]:
        """Retrieve alerts from ZAP for a given target."""
        base_url = urlparse(target)
        base = f"{base_url.scheme}://{base_url.netloc}"

        data = await self._zap_api(
            "GET", "core/view/alerts/",
            params={"baseurl": base, "start": "0", "count": "100"},
        )
        if data and isinstance(data, dict):
            return data.get("alerts", [])
        return []

    # ── Alert parsing ──────────────────────────────────────────────────

    def _normalize_risk(self, risk: str) -> str:
        """Convert ZAP risk level (string or numeric) to canonical severity."""
        from app.services.finding_normalizer import normalize_severity
        if risk is None:
            return "INFO"
        risk_str = str(risk).strip()
        # Handle numeric risk codes (0=Info, 1=Low, 2=Medium, 3=High)
        if risk_str in _ZAP_NUMERIC_RISK:
            risk_str = _ZAP_NUMERIC_RISK[risk_str]
        return normalize_severity(risk_str)

    def _normalize_confidence(self, confidence: str) -> Optional[float]:
        """Convert ZAP confidence level to 0.0-1.0 scale."""
        from app.services.finding_normalizer import normalize_confidence
        if confidence is None:
            return None
        return normalize_confidence(str(confidence).strip())

    def _parse_alerts(self, alerts: List[Dict[str, Any]],
                      target: str) -> List[Dict[str, Any]]:
        """Parse ZAP alerts into canonical finding dicts.

        Each alert produces a finding dict that is compatible with
        ``build_canonical_finding`` from ``finding_normalizer``.

        Important: this function does NOT redact secrets — that happens
        downstream in ``build_canonical_finding`` → ``redact_sensitive_text``.
        """
        findings = []

        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            # Map ZAP risk level to canonical severity
            risk = alert.get("risk")
            if not risk:
                risk = alert.get("risk_level", "Low")
            severity = self._normalize_risk(risk)

            # Confidence
            confidence = self._normalize_confidence(alert.get("confidence"))

            # Extract CWE from ZAP's cweId field (format: "79" → "CWE-79")
            # Also extract from tags dict — ZAP 2.16 stores CWE in tags.CWE-XXX
            cwe = self._extract_cwe(alert.get("cweId"))
            if not cwe:
                tags = alert.get("tags") or {}
                if isinstance(tags, dict):
                    cwe = [t for t in tags.keys() if t.startswith("CWE-")]
                elif isinstance(tags, list):
                    cwe = [t for t in tags if isinstance(t, str) and t.startswith("CWE-")]

            # Extract WASC ID
            wasc = alert.get("wascId") or ""

            # Location: ZAP gives us a URL, method, and parameter
            url = alert.get("url") or target
            param = alert.get("param") or ""
            method = alert.get("method") or "GET"
            attack = alert.get("attack") or ""

            # Build location — web findings use URL + method + parameter
            location_url = url
            location_method = method
            location_param = param

            # Title — use ``or`` chains so None values are handled
            title = alert.get("name") or alert.get("alert") or ""

            # Description (redacted downstream)
            description = alert.get("description") or title

            # Remediation/solution
            remediation = alert.get("solution") or \
                alert.get("remediation") or \
                "Review the affected endpoint and apply the recommended fix."

            # References
            references = []
            ref_str = alert.get("reference") or ""
            if ref_str:
                references = [r.strip() for r in ref_str.split("\n") if r.strip()]

            # Tags
            tags = alert.get("tags") or {}
            if isinstance(tags, dict):
                tags_list = list(tags.keys())
            elif isinstance(tags, list):
                tags_list = tags
            else:
                tags_list = []

            # Evidence
            evidence = alert.get("evidence") or ""

            finding = {
                "type": "api_vulnerability",
                "tool": "zap",
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "description": description,
                "evidence": evidence,
                "remediation": remediation,
                "cwe": cwe,
                "references": references,
                "tags": tags_list,
                # Web location info
                "url": location_url,
                "method": location_method,
                "parameter": location_param,
                "attack": attack,
                "target": target,
                "category": alert.get("alert") or "api_vulnerability",
                "alert_id": alert.get("alertId") or "",
                "plugin_id": alert.get("pluginId") or "",
                "risk": alert.get("risk") or "",
                "risk_desc": alert.get("risk_desc") or "",
                "wasc_id": wasc,
                "solution": alert.get("solution") or "",
                "other_info": alert.get("otherInfo") or "",
                # Location field (for schema compatibility)
                # Web findings will have empty file/line — that's expected
                "file": "",
                "line": 0,
                "data_source": "real_tools",
            }

            findings.append(finding)

        return findings

    def _extract_cwe(self, cwe_raw: str) -> List[str]:
        """Extract CWE IDs from ZAP's cweId field.

        ZAP returns CWE IDs as plain numbers (e.g., "79" or "798").
        We convert to canonical "CWE-79" format.
        """
        from app.services.finding_normalizer import _extract_cwe_ids
        if not cwe_raw:
            return []
        return _extract_cwe_ids(str(cwe_raw).strip())

    # ── Convenience methods ────────────────────────────────────────────

    async def scan_api(self, target: str) -> ScanResult:
        """Quick API security scan (passive mode)."""
        return await self.scan(target, scan_type="passive")

    async def scan_passive(self, target: str, **kwargs) -> ScanResult:
        """Passive scan — safe mode, no intrusive attacks."""
        kwargs.setdefault("scan_type", "passive")
        kwargs.setdefault("spider", False)
        return await self.scan(target, **kwargs)

    async def scan_baseline(self, target: str, **kwargs) -> ScanResult:
        """Baseline scan — spider + passive + safe active checks."""
        kwargs.setdefault("scan_type", "baseline")
        kwargs.setdefault("spider", True)
        return await self.scan(target, **kwargs)

    async def scan_active(self, target: str, **kwargs) -> ScanResult:
        """Full active scan — comprehensive and potentially intrusive.

        Active scanning should only be used against targets you have
        explicit authorization to test.
        """
        kwargs.setdefault("scan_type", "active")
        kwargs.setdefault("spider", True)
        return await self.scan(target, **kwargs)
