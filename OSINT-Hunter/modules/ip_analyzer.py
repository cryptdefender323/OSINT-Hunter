#!/usr/bin/env python3

import os
import json
import socket
import subprocess
import platform
import requests
import re
import time
import dns.resolver
import dns.query
import dns.zone
import dns.name
import ipaddress
import ssl
import concurrent.futures
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

console = Console()

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 11211: "Memcached",
}


class IPAnalyzer:
    def __init__(self, target):
        self.target = target.strip()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.get_random_ua()})
        proxy = Config.get_proxy_dict()
        if proxy:
            self.session.proxies.update(proxy)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5

    def resolve_ip(self):
        try:
            ip = socket.gethostbyname(self.target)
            console.print(f"[green]✓ Resolved {self.target} → {ip}[/green]")
            return ip
        except Exception as e:
            console.print(f"[red]✘ Failed to resolve: {e}[/red]")
            return None

    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_geo_info(self, ip):
        console.print(f"[cyan]→ GeoIP lookup for {ip}[/cyan]")
        geo_data = {}

        try:
            res = self.session.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
                timeout=10
            )
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    geo_data = data
        except Exception:
            pass

        try:
            res2 = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if res2.status_code == 200:
                ipinfo = res2.json()
                geo_data["ipinfo_org"] = ipinfo.get("org", "")
                geo_data["ipinfo_hostname"] = ipinfo.get("hostname", "")
                geo_data["ipinfo_region"] = ipinfo.get("region", "")
        except Exception:
            pass

        return geo_data

    def reverse_dns(self, ip):
        console.print(f"[cyan]→ Reverse DNS lookup[/cyan]")
        try:
            host = socket.gethostbyaddr(ip)
            return host[0]
        except Exception:
            return "N/A"

    def do_ping(self, ip):
        console.print(f"[cyan]→ Ping test to {ip}[/cyan]")
        system = platform.system().lower()
        cmd = ["ping", "-c", "4", ip] if system != "windows" else ["ping", ip, "-n", "4"]
        try:
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10).decode()
            lines = result.strip().splitlines()
            return "\n".join(lines[-3:])
        except Exception as e:
            return f"Ping failed: {e}"

    def get_abuseipdb_report(self, ip):
        api_key = Config.ABUSEIPDB_API_KEY
        if not api_key:
            console.print("[yellow]  ⚠ No AbuseIPDB API key[/yellow]")
            return {}

        console.print(f"[cyan]→ Checking AbuseIPDB for {ip}[/cyan]")
        try:
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            res = self.session.get(url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {})
                return {
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "usage_type": data.get("usageType", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported": data.get("lastReportedAt", "N/A"),
                }
        except Exception as e:
            console.print(f"[red]  AbuseIPDB error: {e}[/red]")
        return {}

    def get_virustotal_report(self, ip):
        api_key = Config.VT_API_KEY
        if not api_key:
            console.print("[yellow]  ⚠ No VirusTotal API key[/yellow]")
            return {}

        console.print(f"[cyan]→ VirusTotal IP report for {ip}[/cyan]")
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": api_key}
            res = self.session.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "as_owner": data.get("as_owner", ""),
                    "asn": data.get("asn", 0),
                    "continent": data.get("continent", ""),
                    "network": data.get("network", ""),
                    "reputation": data.get("reputation", 0),
                }
        except Exception as e:
            console.print(f"[red]  VirusTotal error: {e}[/red]")
        return {}

    def get_shodan_report(self, ip):
        api_key = Config.SHODAN_API_KEY
        if not api_key or not HAS_SHODAN:
            console.print("[yellow]  ⚠ No Shodan API key or library[/yellow]")
            return {}

        console.print(f"[cyan]→ Shodan lookup for {ip}[/cyan]")
        try:
            api = shodan.Shodan(api_key)
            host = api.host(ip)
            return {
                "organization": host.get("org", ""),
                "os": host.get("os", ""),
                "ports": host.get("ports", []),
                "vulns": host.get("vulns", []),
                "hostnames": host.get("hostnames", []),
                "isp": host.get("isp", ""),
                "last_update": host.get("last_update", ""),
                "services": [
                    {"port": s.get("port"), "product": s.get("product", ""), "version": s.get("version", "")}
                    for s in host.get("data", [])[:10]
                ]
            }
        except Exception as e:
            console.print(f"[red]  Shodan error: {e}[/red]")
        return {}

    def port_scan(self, ip, ports=None):
        if ports is None:
            ports = list(SERVICE_MAP.keys())
        console.print(f"[cyan]→ Scanning {len(ports)} common ports[/cyan]")
        open_ports = {}

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    banner = self._grab_banner(ip, port)
                    return port, {
                        "service": SERVICE_MAP.get(port, "unknown"),
                        "banner": banner,
                        "state": "open"
                    }
            except Exception:
                pass
            return port, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(scan_port, p) for p in ports]
            for future in concurrent.futures.as_completed(futures):
                port, info = future.result()
                if info:
                    open_ports[port] = info

        return open_ports

    def _grab_banner(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            if port in [443, 8443]:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=ip)
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            banner = sock.recv(1024).decode(errors='ignore').strip()
            sock.close()
            return banner[:200] if banner else ""
        except Exception:
            return ""

    def check_tor_exit(self, ip):
        console.print("[cyan]→ Checking Tor exit node status[/cyan]")
        try:
            reversed_ip = ".".join(reversed(ip.split(".")))
            query = f"{reversed_ip}.dnsel.torproject.org"
            answers = self.resolver.resolve(query, 'A')
            for rdata in answers:
                if str(rdata) == "127.0.0.2":
                    return True
        except Exception:
            pass
        return False

    def run(self):
        ip = self.resolve_ip()
        if not ip:
            console.print("[red]✘ Could not resolve IP.[/red]")
            return

        console.print(Panel(
            f"[bold cyan]IP ANALYZER — {ip}[/bold cyan]\n"
            f"[dim]GeoIP • Ports • Shodan • VirusTotal • AbuseIPDB • Tor Check[/dim]",
            border_style="cyan"
        ))

        result = {
            "target": self.target,
            "ip_address": ip,
            "scan_time": datetime.now().isoformat(),
            "geoip": {},
            "reverse_dns": "",
            "abuseipdb": {},
            "virustotal": {},
            "shodan": {},
            "ping": "",
            "open_ports": {},
            "is_tor_exit": False,
            "threat_score": 0,
        }

        result["geoip"] = self.get_geo_info(ip)
        result["reverse_dns"] = self.reverse_dns(ip)
        result["ping"] = self.do_ping(ip)
        result["abuseipdb"] = self.get_abuseipdb_report(ip)
        result["virustotal"] = self.get_virustotal_report(ip)
        result["shodan"] = self.get_shodan_report(ip)
        result["open_ports"] = self.port_scan(ip)
        result["is_tor_exit"] = self.check_tor_exit(ip)

        threat = 0
        abuse = result.get("abuseipdb", {})
        vt = result.get("virustotal", {})
        if abuse.get("abuse_confidence", 0) > 50:
            threat += 30
        if abuse.get("total_reports", 0) > 10:
            threat += 15
        if abuse.get("is_tor", False):
            threat += 10
        if vt.get("malicious", 0) > 3:
            threat += 25
        if vt.get("suspicious", 0) > 2:
            threat += 10
        if result["is_tor_exit"]:
            threat += 10
        result["threat_score"] = min(threat, 100)

        geo = result["geoip"]
        geo_table = Table(title="GeoIP Information", show_header=False)
        geo_table.add_column("Field", style="cyan", width=20)
        geo_table.add_column("Value", style="white")
        for field in ["country", "regionName", "city", "zip", "lat", "lon", "timezone", "isp", "org", "as", "asname"]:
            if geo.get(field):
                geo_table.add_row(field.replace("Name", " Name").title(), str(geo[field]))
        geo_table.add_row("Reverse DNS", result["reverse_dns"])
        geo_table.add_row("Is Proxy/VPN", str(geo.get("proxy", "N/A")))
        geo_table.add_row("Is Hosting", str(geo.get("hosting", "N/A")))
        geo_table.add_row("Is Tor Exit", "[red]YES[/red]" if result["is_tor_exit"] else "[green]NO[/green]")
        console.print(geo_table)

        if result["open_ports"]:
            port_table = Table(title="Open Ports", show_header=True, header_style="bold green")
            port_table.add_column("Port", style="cyan", width=8)
            port_table.add_column("Service", style="yellow", width=15)
            port_table.add_column("Banner", style="dim")
            for port in sorted(result["open_ports"].keys()):
                info = result["open_ports"][port]
                port_table.add_row(str(port), info["service"], info["banner"][:60] if info["banner"] else "—")
            console.print(port_table)

        if abuse:
            abuse_table = Table(title="AbuseIPDB Report", show_header=False)
            abuse_table.add_column("Field", style="cyan")
            abuse_table.add_column("Value", style="magenta")
            for k, v in abuse.items():
                abuse_table.add_row(k.replace("_", " ").title(), str(v))
            console.print(abuse_table)

        if vt:
            vt_color = "red" if vt.get("malicious", 0) > 0 else "green"
            console.print(Panel(
                f"[{vt_color}]Malicious: {vt.get('malicious', 0)}[/{vt_color}]  |  "
                f"Suspicious: {vt.get('suspicious', 0)}  |  "
                f"Harmless: {vt.get('harmless', 0)}  |  "
                f"Reputation: {vt.get('reputation', 0)}",
                title="VirusTotal Report",
                border_style=vt_color
            ))

        t_color = "green" if result["threat_score"] < 30 else ("yellow" if result["threat_score"] < 60 else "red")
        console.print(Panel(
            f"[{t_color}]Threat Score: {result['threat_score']}/100[/{t_color}]",
            title="Threat Assessment",
            border_style=t_color
        ))

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        Config.ensure_dirs()
        filename = f"logs/ip_analyze_{ip}_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n[green]✔ Report saved to {filename}[/green]")


def main():
    console.print(Panel(
        "[bold cyan]IP ANALYZER — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]GeoIP • Port Scan • Shodan • VirusTotal • AbuseIPDB • Tor Detection[/dim]",
        border_style="cyan"
    ))
    target = input("\n  Enter target domain or IP address: ").strip()
    analyzer = IPAnalyzer(target)
    analyzer.run()


if __name__ == "__main__":
    main()