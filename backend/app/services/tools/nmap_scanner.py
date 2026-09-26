"""
Nmap scanner for network reconnaissance.
Used by the Recon Agent to discover open ports, services, and hosts.
"""
import asyncio
import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from app.services.tools.base import BaseScanner, ScanResult, ScanStatus


class NmapScanner(BaseScanner):
    """Nmap network scanner wrapper."""
    
    @property
    def tool_name(self) -> str:
        return "Nmap"
    
    @property
    def command_name(self) -> str:
        return "nmap"
    
    async def scan(self, target: str, **kwargs) -> ScanResult:
        """
        Run Nmap scan against target.
        
        Args:
            target: Target URL or IP address
            scan_type: Type of scan (syn, connect, udp, comprehensive)
            ports: Port range to scan (e.g., "1-1000", "top100")
            extra_args: Additional nmap arguments
            
        Returns:
            ScanResult with discovered hosts, ports, and services
        """
        import time
        start_time = time.time()
        
        # Check if nmap is installed
        if not await self.check_installed():
            return self.create_not_installed_result()
        
        # Extract target host from URL
        host = self._extract_host(target)
        if not host:
            return self.create_failed_result("Could not extract host from target")
        
        # Build nmap command
        args = [self.command_name]
        
        # Scan type
        scan_type = kwargs.get("scan_type", "syn")
        if scan_type == "syn":
            args.append("-sS")
        elif scan_type == "connect":
            args.append("-sT")
        elif scan_type == "udp":
            args.append("-sU")
        elif scan_type == "comprehensive":
            args.extend(["-sS", "-sU", "-A"])
        
        # Port specification
        ports = kwargs.get("ports", "top100")
        if ports == "all":
            args.append("-p-")
        elif ports == "top100":
            args.extend(["--top-ports", "100"])
        elif ports == "top1000":
            args.extend(["--top-ports", "1000"])
        else:
            args.extend(["-p", ports])
        
        # Service detection
        args.extend(["-sV", "--version-intensity", "5"])
        
        # OS detection
        if kwargs.get("os_detection", False):
            args.append("-O")
        
        # Output format
        args.extend(["-oX", "-"])  # XML output to stdout
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Target
        args.append(host)
        
        # Run scan
        returncode, stdout, stderr = await self.run_command(args)
        duration = time.time() - start_time
        
        if returncode != 0 and returncode != 1:  # nmap returns 1 when no hosts found
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.FAILED,
                findings=[],
                raw_output=stdout,
                error=stderr,
                duration_seconds=duration
            )
        
        # Parse XML output
        findings = self._parse_xml_output(stdout)
        
        return ScanResult(
            tool_name=self.tool_name,
            status=ScanStatus.SUCCESS,
            findings=findings,
            raw_output=stdout,
            duration_seconds=duration
        )
    
    def _extract_host(self, target: str) -> str:
        """Extract hostname/IP from target URL."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]  # Remove port if present
        except Exception:
            # Assume it's already a hostname/IP
            return target.split(":")[0]
    
    def _parse_xml_output(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output into findings."""
        findings = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue
                
                # Get host address
                address = host.find("address")
                host_ip = address.get("addr") if address is not None else "unknown"
                
                # Get hostnames
                hostnames = []
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall("hostname"):
                        hostnames.append(hostname.get("name"))
                
                # Get ports
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")
                        
                        state_elem = port.find("state")
                        state = state_elem.get("state") if state_elem is not None else "unknown"
                        
                        service_elem = port.find("service")
                        service_info = {}
                        if service_elem is not None:
                            service_info = {
                                "name": service_elem.get("name"),
                                "product": service_elem.get("product"),
                                "version": service_elem.get("version"),
                                "extrainfo": service_elem.get("extrainfo"),
                                "tunnel": service_elem.get("tunnel"),
                            }
                        
                        if state == "open":
                            findings.append({
                                "type": "open_port",
                                "severity": "INFO",
                                "host": host_ip,
                                "hostnames": hostnames,
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": service_info,
                                "description": f"Open {protocol} port {port_id} on {host_ip}",
                                "remediation": "Verify if this port/service should be publicly accessible"
                            })
                
                # OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    for osmatch in os_elem.findall("osmatch"):
                        findings.append({
                            "type": "os_detection",
                            "severity": "INFO",
                            "host": host_ip,
                            "os_name": osmatch.get("name"),
                            "accuracy": osmatch.get("accuracy"),
                            "description": f"OS detected: {osmatch.get('name')} ({osmatch.get('accuracy')}% accuracy)",
                        })
        
        except ET.ParseError as e:
            # If XML parsing fails, try to extract basic info from text output
            pass
        
        return findings
    
    async def quick_scan(self, target: str) -> ScanResult:
        """Quick scan for common ports."""
        return await self.scan(target, scan_type="syn", ports="top100")
    
    async def comprehensive_scan(self, target: str) -> ScanResult:
        """Comprehensive scan with OS and service detection."""
        return await self.scan(target, scan_type="comprehensive", ports="top1000", os_detection=True)