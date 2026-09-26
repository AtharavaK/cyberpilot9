"""
OWASP ZAP scanner for API security testing.
Used by the API Security Agent to find API vulnerabilities.
"""
import asyncio
import json
import aiohttp
from typing import Dict, Any, List, Optional
from app.services.tools.base import BaseScanner, ScanResult, ScanStatus


class ZapScanner(BaseScanner):
    """OWASP ZAP API security scanner wrapper."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.zap_url = self.config.get("zap_url", "http://localhost:8080")
        self.api_key = self.config.get("api_key", "")
        self.session = None
    
    @property
    def tool_name(self) -> str:
        return "OWASP ZAP"
    
    @property
    def command_name(self) -> str:
        return "zap-api-scan.py"
    
    async def check_installed(self) -> bool:
        """Check if ZAP is running and accessible."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.zap_url}/JSON/core/view/version/",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False
    
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run ZAP scan against target API.
        
        Args:
            target: Target API URL
            scan_type: Type of scan (quick, full, auth)
            context: ZAP context name
            extra_args: Additional ZAP arguments
            
        Returns:
            ScanResult with API security findings
        """
        import time
        start_time = time.time()
        
        # Check if ZAP is running
        if not await self.check_installed():
            return self.create_not_installed_result()
        
        scan_type = kwargs.get("scan_type", "quick")
        
        if scan_type == "quick":
            return await self._quick_scan(target, kwargs)
        elif scan_type == "full":
            return await self._full_scan(target, kwargs)
        elif scan_type == "auth":
            return await self._auth_scan(target, kwargs)
        else:
            return await self._quick_scan(target, kwargs)
    
    async def _quick_scan(self, target: str, kwargs: Dict) -> ScanResult:
        """Run a quick passive scan."""
        import time
        start_time = time.time()
        
        try:
            # Access target to populate ZAP's site tree
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    await resp.text()
            
            # Run quick active scan
            scan_id = await self._start_active_scan(target)
            if not scan_id:
                return ScanResult(
                    tool_name=self.tool_name,
                    status=ScanStatus.FAILED,
                    findings=[],
                    error="Failed to start active scan",
                    duration_seconds=time.time() - start_time
                )
            
            # Wait for scan completion
            await self._wait_for_scan(scan_id)
            
            # Get alerts
            alerts = await self._get_alerts(target)
            
            findings = self._parse_alerts(alerts)
            
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.SUCCESS,
                findings=findings,
                duration_seconds=time.time() - start_time
            )
        
        except Exception as e:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                error=str(e),
                duration_seconds=time.time() - start_time
            )
    
    async def _full_scan(self, target: str, kwargs: Dict) -> ScanResult:
        """Run a comprehensive active scan with spidering."""
        import time
        start_time = time.time()
        
        try:
            # Spider the target
            spider_id = await self._start_spider(target)
            if spider_id:
                await self._wait_for_spider(spider_id)
            
            # Active scan
            scan_id = await self._start_active_scan(target)
            if not scan_id:
                return ScanResult(
                    tool_name=self.tool_name,
                    status=ScanStatus.FAILED,
                    findings=[],
                    error="Failed to start active scan",
                    duration_seconds=time.time() - start_time
                )
            
            await self._wait_for_scan(scan_id)
            
            alerts = await self._get_alerts(target)
            findings = self._parse_alerts(alerts)
            
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.SUCCESS,
                findings=findings,
                duration_seconds=time.time() - start_time
            )
        
        except Exception as e:
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                error=str(e),
                duration_seconds=time.time() - start_time
            )
    
    async def _auth_scan(self, target: str, kwargs: Dict) -> ScanResult:
        """Run authenticated scan with provided credentials."""
        # For simplicity, fall back to full scan
        # In production, would set up authentication context
        return await self._full_scan(target, kwargs)
    
    async def _start_spider(self, target: str) -> Optional[str]:
        """Start spider scan."""
        try:
            async with aiohttp.ClientSession() as session:
                params = {"url": target}
                if self.api_key:
                    params["apikey"] = self.api_key
                
                async with session.get(
                    f"{self.zap_url}/JSON/spider/action/scan/",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    data = await resp.json()
                    return data.get("scan")
        except Exception:
            pass
        return None
    
    async def _wait_for_spider(self, spider_id: str, max_wait: int = 120) -> bool:
        """Wait for spider to complete."""
        try:
            for _ in range(max_wait):
                async with aiohttp.ClientSession() as session:
                    params = {"scanId": spider_id}
                    if self.api_key:
                        params["apikey"] = self.api_key
                    
                    async with session.get(
                        f"{self.zap_url}/JSON/spider/view/status/",
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        data = await resp.json()
                        status = int(data.get("status", 0))
                        if status >= 100:
                            return True
                        await asyncio.sleep(2)
        except Exception:
            pass
        return False
    
    async def _start_active_scan(self, target: str) -> Optional[str]:
        """Start active scan."""
        try:
            async with aiohttp.ClientSession() as session:
                params = {"url": target, "recurse": "true"}
                if self.api_key:
                    params["apikey"] = self.api_key
                
                async with session.get(
                    f"{self.zap_url}/JSON/ascan/action/scan/",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    data = await resp.json()
                    return data.get("scan")
        except Exception:
            pass
        return None
    
    async def _wait_for_scan(self, scan_id: str, max_wait: int = 300) -> bool:
        """Wait for active scan to complete."""
        try:
            for _ in range(max_wait):
                async with aiohttp.ClientSession() as session:
                    params = {"scanId": scan_id}
                    if self.api_key:
                        params["apikey"] = self.api_key
                    
                    async with session.get(
                        f"{self.zap_url}/JSON/ascan/view/status/",
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        data = await resp.json()
                        status = int(data.get("status", 0))
                        if status >= 100:
                            return True
                        await asyncio.sleep(5)
        except Exception:
            pass
        return False
    
    async def _get_alerts(self, target: str) -> List[Dict[str, Any]]:
        """Get alerts from ZAP."""
        try:
            async with aiohttp.ClientSession() as session:
                params = {"baseurl": target}
                if self.api_key:
                    params["apikey"] = self.api_key
                
                async with session.get(
                    f"{self.zap_url}/JSON/core/view/alerts/",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    data = await resp.json()
                    return data.get("alerts", [])
        except Exception:
            pass
        return []
    
    def _parse_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse ZAP alerts into findings."""
        findings = []
        
        for alert in alerts:
            # Map risk level to severity
            risk_map = {
                "High": "HIGH",
                "Medium": "MEDIUM",
                "Low": "LOW",
                "Informational": "INFO"
            }
            
            risk = alert.get("risk", "Low")
            severity = risk_map.get(risk, "INFO")
            
            findings.append({
                "type": "api_vulnerability",
                "tool": "zap",
                "alert_id": alert.get("pluginId", ""),
                "name": alert.get("name", ""),
                "severity": severity,
                "confidence": alert.get("confidence", "Medium"),
                "description": alert.get("description", ""),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
                "evidence": alert.get("evidence", ""),
                "cwe": alert.get("cweId", ""),
                "wasc": alert.get("wascId", ""),
                "reference": alert.get("reference", ""),
                "solution": alert.get("solution", ""),
                "remediation": alert.get("solution", "") or "Review the API endpoint and apply the recommended fix.",
                "tags": alert.get("tags", [])
            })
        
        return findings
    
    async def scan_api(self, target: str) -> ScanResult:
        """Quick API security scan."""
        return await self._quick_scan(target, {})
    
    async def scan_with_auth(self, target: str, auth_config: Dict) -> ScanResult:
        """Scan with authentication (requires ZAP context setup)."""
        # Placeholder for authenticated scans
        return await self._full_scan(target, {})