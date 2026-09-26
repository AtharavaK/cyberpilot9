"""
Base tool interface for security scanners.
All scanners should inherit from BaseScanner and implement the scan method.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio
import subprocess
import json
import logging

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_INSTALLED = "not_installed"


@dataclass
class ScanResult:
    """Result of a security tool scan."""
    tool_name: str
    status: ScanStatus
    findings: List[Dict[str, Any]]
    raw_output: str = ""
    error: str = ""
    duration_seconds: float = 0.0


class BaseScanner(ABC):
    """Abstract base class for security tool scanners."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 300)
        self.enabled = self.config.get("enabled", True)
    
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Human-readable name of the tool."""
        pass
    
    @property
    @abstractmethod
    def command_name(self) -> str:
        """Command to check if tool is installed."""
        pass
    
    @abstractmethod
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """Run the scanner against a target."""
        pass
    
    async def check_installed(self) -> bool:
        """Check if the tool is installed and available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.command_name, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            return proc.returncode == 0
        except Exception:
            return False
    
    async def run_command(self, args: List[str], cwd: str = None) -> tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), 
                    timeout=self.timeout
                )
                return proc.returncode, stdout.decode('utf-8', errors='replace'), stderr.decode('utf-8', errors='replace')
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return -1, "", f"Command timed out after {self.timeout} seconds"
        except FileNotFoundError:
            return -1, "", f"Command not found: {args[0]}"
        except Exception as e:
            return -1, "", str(e)
    
    def create_failed_result(self, error: str, duration: float = 0.0) -> ScanResult:
        """Create a failed scan result."""
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.FAILED,
            findings=[],
            error=error,
            duration_seconds=duration
        )
    
    def create_not_installed_result(self) -> ScanResult:
        """Create a not installed scan result."""
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.NOT_INSTALLED,
            findings=[],
            error=f"{self.tool_name} is not installed or not in PATH"
        )
    
    def create_timeout_result(self, duration: float) -> ScanResult:
        """Create a timeout scan result."""
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.TIMEOUT,
            findings=[],
            error=f"Scan timed out after {duration} seconds",
            duration_seconds=duration
        )