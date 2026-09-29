"""
Nmap scanner for network reconnaissance.
Used by the Recon Agent to discover open ports, services, and hosts.
"""
import asyncio
import xml.etree.ElementTree as ET
import ipaddress
from typing import Dict, Any, List, Tuple
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
            target: Target URL, IP address, hostname, or CIDR range
            scan_type: Type of scan (syn, connect, udp, comprehensive, ping,
                       traceroute, vuln, default)
            ports: Port range to scan (e.g., "1-1000", "top100", "all", "80,443")
            extra_args: Additional nmap arguments
            allow_internal: If True, allow scanning private/internal IPs.
                When False (default), private/internal targets are rejected
                to prevent accidental SSRF-like abuse against internal networks.
            scan_coordinate: optional dict recorded for audit (who authorized this scan).
            os_detection: Enable OS detection (-O)
            service_detection: Enable service/version detection (-sV)
            version_intensity: Intensity level 0-9 for version detection
            scripts: NSE script category or comma-separated script names
                       (e.g., "default", "vuln", "ssl-enum-ciphers", "smb-os-discovery")
            traceroute: Enable traceroute (--traceroute)
            ipv6: Treat target as IPv6
            host_discovery_only: Host discovery only (-sn, no port scan)
            dns_servers: Custom DNS servers to use
            anonymous_checks: Enable checks for anonymous service access
                           (FTP anonymous, SMTP open relay, etc.)
            text_output: Also save scan results in normal text format (-oN)

        Returns:
            ScanResult with discovered hosts, ports, services, OS, scripts, routes
        """
        import time
        start_time = time.time()

        # Check if nmap is installed
        if not await self.check_installed():
            return self.create_not_installed_result()

        # Extract target host and validate
        allow_internal = kwargs.get("allow_internal", False)
        host, is_private = self._classify_host(target, allow_internal)
        
        # Build nmap command
        args = [self.command_name]
        
        # Host discovery only mode
        if kwargs.get("host_discovery_only", False):
            args.append("-sn")
            args.extend(["-oX", "-"])
            extra_args = kwargs.get("extra_args", [])
            args.extend(extra_args)
            args.append(host)
            returncode, stdout, stderr = await self.run_command(args)
            duration = time.time() - start_time
            if returncode != 0 and returncode != 1:
                return ScanResult(
                    tool_name=self.tool_name,
                    status=ScanStatus.FAILED,
                    findings=[],
                    raw_output=stdout,
                    error=stderr,
                    duration_seconds=duration
                )
            findings = self._parse_xml_output(stdout)
            return ScanResult(
                tool_name=self.tool_name,
                status=ScanStatus.SUCCESS,
                findings=findings,
                raw_output=stdout,
                duration_seconds=duration
            )
        
        # Default ports if not specified
        ports = kwargs.get("ports", "top100")
        
        # Scan type
        scan_type = kwargs.get("scan_type", "connect")
        if scan_type == "syn":
            args.append("-sS")
        elif scan_type == "connect":
            args.append("-sT")
        elif scan_type == "udp":
            args.append("-sU")
        elif scan_type == "ping":
            args.append("-sn")
            ports = None  # No port scan
        elif scan_type == "comprehensive":
            args.append("-A")
        elif scan_type == "traceroute":
            args.append("--traceroute")
        elif scan_type == "vuln":
            args.append("-O")
            args.append("-sV")
            scripts_val = kwargs.get("scripts", "vuln")
            if scripts_val:
                args.extend(["--script", scripts_val])
        elif scan_type == "default":
            args.append("-sC")
            args.append("-sV")
        
        # IPv6 support
        if kwargs.get("ipv6", False):
            args.append("-6")
        
        # DNS servers
        dns_servers = kwargs.get("dns_servers", "")
        if dns_servers:
            args.extend(["--dns-servers", dns_servers])
        
        # Port specification (skip if ping/traceroute-only mode)
        if ports is not None:
            if ports == "all":
                args.append("-p-")
            elif ports == "top100":
                args.extend(["--top-ports", "100"])
            elif ports == "top1000":
                args.extend(["--top-ports", "1000"])
            else:
                args.extend(["-p", ports])
        
        # Service detection
        if kwargs.get("service_detection", True):
            args.append("-sV")
            intensity = kwargs.get("version_intensity", 5)
            if intensity is not None:
                args.extend(["--version-intensity", str(intensity)])
        
        # OS detection
        if kwargs.get("os_detection", False):
            args.append("-O")
            if kwargs.get("os_aggressive", False):
                args.append("--osscan-guess")
        
        # Traceroute
        if kwargs.get("traceroute", False) and scan_type not in ("traceroute", "comprehensive"):
            args.append("--traceroute")
        
        # NSE scripts (if not already set by vuln/default scan_type)
        scripts = kwargs.get("scripts", "")
        if scripts and scan_type not in ("vuln", "default"):
            args.extend(["--script", scripts])
        
        # Extra arguments
        extra_args = kwargs.get("extra_args", [])
        args.extend(extra_args)
        
        # Output: XML to stdout
        args.extend(["-oX", "-"])
        
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
    
    @staticmethod
    def _extract_host(target: str) -> str:
        """Extract hostname/IP from target URL or raw target.

        Handles:
        - URLs: http://host:port → host
        - Raw IPs: 192.168.1.1 → 192.168.1.1
        - CIDR ranges: 192.168.1.0/24 → 192.168.1.0/24  (network scan)
        - IPv6: ::1 → ::1, 2001:db8::1 → 2001:db8::1
        - Hostnames: example.com → example.com
        """
        from urllib.parse import urlparse

        # If it looks like a URL, extract host
        if "://" in target:
            try:
                parsed = urlparse(target)
                host_part = parsed.netloc.split(":")[0]
                # If there's a path with a / it might be a CIDR in URL form — use netloc
                return host_part
            except Exception:
                pass

        # Raw target: could be IP, CIDR, IPv6, or hostname
        # Detect CIDR notation
        if "/" in target and not target.startswith("["):
            # Could be CIDR like 192.168.1.0/24 or 2001:db8::/32
            # Validate it's a network, not a URL path
            try:
                if ":" in target:
                    ipaddress.IPv6Network(target)
                else:
                    ipaddress.IPv4Network(target)
                return target  # It's a valid CIDR network
            except (ValueError, ipaddress.AddressValueError):
                pass  # Not a valid CIDR, fall through

        # Detect IPv6 address (with or without brackets)
        if ":" in target:
            clean = target.strip("[]")
            try:
                ipaddress.IPv6Address(clean)
                return clean
            except (ValueError, ipaddress.AddressValueError):
                pass  # Not IPv6, could be hostname with port

        # Plain IP or hostname
        return target

    @staticmethod
    def _classify_host(target: str, allow_internal: bool) -> Tuple[str, bool]:
        """Validate target and return (host, is_private).

        Used by the nmap scanner. Handles raw IPs, CIDR ranges, IPv6, hostnames,
        and URLs — unlike the general classify_target which requires http:// scheme.
        """
        host = NmapScanner._extract_host(target)

        # If it's a CIDR network range, allow it (network scan)
        if "/" in host:
            try:
                net = ipaddress.IPv4Network(host, strict=False) if ":" not in host else ipaddress.IPv6Network(host, strict=False)
                return (host, net.is_private or net.is_loopback or net.is_link_local)
            except (ValueError, ipaddress.AddressValueError):
                pass

        # Try as literal IP
        try:
            ip = ipaddress.ip_address(host)
            is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            if not allow_internal and is_private:
                raise ValueError(
                    f"Scanning private/internal targets is not allowed by default. "
                    f"Target {host!r} is a private/internal address. "
                    f"Set allow_internal=True only when you have explicit authorization."
                )
            return (host, is_private)
        except ValueError:
            pass  # Not a literal IP

        # Hostname — resolve and check
        try:
            from app.services.target_validation import _resolve_host as _r
            resolved = _r(host)
            if resolved is None:
                raise ValueError(f"Could not resolve hostname: {host!r}")
            ip = ipaddress.ip_address(resolved)
            is_private = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            if not allow_internal and is_private:
                raise ValueError(
                    f"Scanning private/internal targets is not allowed by default. "
                    f"Target {host!r} resolves to {resolved!r} (private/internal). "
                    f"Set allow_internal=True only when you have explicit authorization."
                )
            return (host, is_private)
        except ValueError:
            raise
    
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
                addr_type = address.get("addrtype") if address is not None else "ipv4"

                # Get hostnames
                hostnames = []
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall("hostname"):
                        hostnames.append(hostname.get("name"))

                # ── Host discovery (ping mode) finding ──
                if not host.find("ports"):  # no ports element = ping/host discovery scan
                    reason_elem = host.find("status")
                    reason = reason_elem.get("reason") if reason_elem is not None else "unknown"
                    findings.append({
                        "type": "host_up",
                        "severity": "INFO",
                        "host": host_ip,
                        "hostnames": hostnames,
                        "addrtype": addr_type,
                        "reason": reason,
                        "description": f"Host {host_ip} is up ({reason})",
                        "remediation": "Verify this host is authorized and properly secured",
                    })
                    # OS guess from status
                    os_elem_guess = host.find("os")
                    if os_elem_guess is not None:
                        for osmatch in os_elem_guess.findall("osmatch"):
                            findings.append({
                                "type": "os_detection",
                                "severity": "INFO",
                                "host": host_ip,
                                "os_name": osmatch.get("name"),
                                "accuracy": osmatch.get("accuracy"),
                                "description": f"OS detected: {osmatch.get('name')} ({osmatch.get('accuracy')}% accuracy)",
                            })
                    continue

                # ── Ports (all states: open, closed, filtered, unfiltered) ──
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port in ports_elem.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")

                        state_elem = port.find("state")
                        state = state_elem.get("state") if state_elem is not None else "unknown"
                        reason = state_elem.get("reason") if state_elem is not None else ""

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

                        # Open ports
                        if state == "open":
                            findings.append({
                                "type": "open_port",
                                "severity": "INFO",
                                "host": host_ip,
                                "hostnames": hostnames,
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": service_info,
                                "reason": reason,
                                "description": f"Open {protocol} port {port_id} on {host_ip}"
                                       + (f" — {service_info.get('name', '')}"
                                          if service_info.get('name') else ""),
                                "remediation": "Verify if this port/service should be publicly accessible",
                            })
                        # Closed ports — note them (unexpected closed can indicate ACL issues)
                        elif state == "closed":
                            findings.append({
                                "type": "closed_port",
                                "severity": "LOW",
                                "host": host_ip,
                                "hostnames": hostnames,
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": service_info,
                                "reason": reason,
                                "description": f"Closed {protocol} port {port_id} on {host_ip}"
                                       + (f" — {service_info.get('name', '')}"
                                          if service_info.get('name') else ""),
                                "remediation": "Investigate why this port is closed; may indicate misconfiguration",
                            })
                        # Filtered ports — firewall/IDS evidence
                        elif state == "filtered":
                            findings.append({
                                "type": "filtered_port",
                                "severity": "MEDIUM",
                                "host": host_ip,
                                "hostnames": hostnames,
                                "port": int(port_id),
                                "protocol": protocol,
                                "service": service_info,
                                "reason": reason,
                                "description": f"Filtered {protocol} port {port_id} on {host_ip}"
                                       + (f" — {service_info.get('name', '')}"
                                          if service_info.get('name') else ""),
                                "remediation": "Review firewall rules; filtered ports may indicate security controls or misconfigured ACLs",
                            })

                # ── OS detection ──
                os_elem = host.find("os")
                if os_elem is not None:
                    # Primary OS matches
                    for osmatch in os_elem.findall("osmatch"):
                        og = osmatch.get("accuracy", "0")
                        findings.append({
                            "type": "os_detection",
                            "severity": "INFO",
                            "host": host_ip,
                            "os_name": osmatch.get("name"),
                            "accuracy": og,
                            "description": f"OS detected: {osmatch.get('name')} ({og}% accuracy)",
                        })
                    # Device type from OS class
                    for osclass in os_elem.findall("osclass"):
                        otype = osclass.get("type", "")
                        ofamily = osclass.get("family", "")
                        odevice = osclass.get("device", "")
                        if otype:
                            desc_parts = [f"device type: {otype}"]
                            if ofamily:
                                desc_parts.append(f"family: {ofamily}")
                            if odevice:
                                desc_parts.append(f"device: {odevice}")
                            findings.append({
                                "type": "device_type",
                                "severity": "INFO",
                                "host": host_ip,
                                "device_type": otype,
                                "device_family": ofamily,
                                "device": odevice,
                                "description": " / ".join(desc_parts),
                            })

                # ── Traceroute ──
                trace_elem = host.find("trace")
                if trace_elem is not None:
                    hops = []
                    for hop in trace_elem.findall("hop"):
                        hop_ip = hop.get("ip", "")
                        hop_rtt = hop.get("rtt", "")
                        hops.append(f"{hop_ip}({hop_rtt}ms)" if hop_rtt else hop_ip)
                    if hops:
                        findings.append({
                            "type": "traceroute",
                            "severity": "INFO",
                            "host": host_ip,
                            "target": host_ip,
                            "hops": hops,
                            "hop_count": len(hops),
                            "description": f"Route to {host_ip}: {' -> '.join(hops)}",
                        })

                # NSE Script output
                script_ports = host.find("ports")
                if script_ports is not None:
                    for port in script_ports.findall("port"):
                        pid = port.get("portid")
                        proto = port.get("protocol", "")
                        for script in port.findall("script"):
                            script_id = script.get("id", "")
                            script_output = script.text.strip() if script.text else ""
                            script_attrs = {k: v for k, v in script.attrib.items()
                                            if k not in ("id", "output", "num")}
                            if script_id and pid:
                                try:
                                    port_num = int(pid)
                                except (ValueError, TypeError):
                                    port_num = 0
                                findings.append({
                                    "type": "nse_script",
                                    "severity": "INFO",
                                    "host": host_ip,
                                    "port": port_num,
                                    "protocol": proto,
                                    "script_id": script_id,
                                    "script_output": script_output[:500] if script_output else "",
                                    "script_attrs": script_attrs,
                                    "description": f"NSE script {script_id} on {proto}/{pid}: {script_output[:200]}"
                                               if script_output else f"NSE script {script_id} on {proto}/{pid}",
                                })

        except ET.ParseError as e:
            # If XML parsing fails, try to extract basic info from text output
            pass

        return findings
    
    async def quick_scan(self, target: str) -> ScanResult:
        """Quick scan for common ports."""
        return await self.scan(target, scan_type="connect", ports="top100")

    async def comprehensive_scan(self, target: str) -> ScanResult:
        """Comprehensive scan with OS, version, script scanning, and traceroute."""
        return await self.scan(
            target,
            scan_type="comprehensive",
            ports="top1000",
            os_detection=True,
            traceroute=True,
        )

    async def ping_scan(self, target: str) -> ScanResult:
        """Host discovery only — find live hosts without port scanning."""
        return await self.scan(target, scan_type="ping")

    async def udp_scan(self, target: str) -> ScanResult:
        """UDP port scan."""
        return await self.scan(target, scan_type="udp", ports="top100")

    async def traceroute_scan(self, target: str) -> ScanResult:
        """Trace network routes to target."""
        return await self.scan(target, scan_type="traceroute", ports="top100")

    async def vuln_scan(self, target: str) -> ScanResult:
        """Vulnerability scan with NSE scripts (default vuln category)."""
        return await self.scan(
            target,
            scan_type="vuln",
            ports="top1000",
            os_detection=True,
        )

    async def default_script_scan(self, target: str) -> ScanResult:
        """Scan with default NSE scripts (-sC) plus version detection."""
        return await self.scan(target, scan_type="default", ports="top100")

    async def ssl_tls_scan(self, target: str) -> ScanResult:
        """SSL/TLS configuration scan using NSE scripts."""
        return await self.scan(
            target,
            scan_type="connect",
            ports="443,8443,9443",
            scripts="ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ccs-injection",
            service_detection=True,
        )

    async def smb_scan(self, target: str) -> ScanResult:
        """SMB enumeration scan."""
        return await self.scan(
            target,
            scan_type="connect",
            ports="139,445",
            scripts="smb-os-discovery,smb-brute,smb-enum-shares,smb-enum-users,smb-vuln-ms17-010",
            service_detection=True,
        )

    async def dns_scan(self, target: str) -> ScanResult:
        """DNS discovery scan."""
        return await self.scan(
            target,
            scan_type="connect",
            ports="53",
            scripts="dns-brute,dns-zone-transfer,dns-srv-records,dns-zone-transferv2",
            service_detection=True,
        )

    async def snmp_scan(self, target: str) -> ScanResult:
        """SNMP enumeration scan."""
        return await self.scan(
            target,
            scan_type="udp",
            ports="161",
            scripts="snmp-brute,snmp-hp-kmip-default,asn-query",
            service_detection=True,
        )