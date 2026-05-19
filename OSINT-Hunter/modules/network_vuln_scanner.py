#!/usr/bin/env python3

import os, json, sys, socket, ssl, requests, re, concurrent.futures
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()

SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",587:"Submission",
    993:"IMAPS",995:"POP3S",1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
    5900:"VNC",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",9200:"Elasticsearch",
    27017:"MongoDB",11211:"Memcached",2049:"NFS",5601:"Kibana",8888:"HTTP-Proxy",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options",
    "X-Frame-Options","X-XSS-Protection","Referrer-Policy","Permissions-Policy",
]

class NetworkVulnScanner:
    def __init__(self, target):
        self.target = target.strip()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.get_random_ua()})
        p = Config.get_proxy_dict()
        if p: self.session.proxies = p

    def resolve(self):
        try:
            ip = socket.gethostbyname(self.target)
            console.print(f"[green]✓ Resolved: {self.target} → {ip}[/green]")
            return ip
        except:
            console.print("[red]✘ Resolution failed[/red]"); return None

    def port_scan(self, ip, ports=None):
        if ports is None: ports = list(SERVICES.keys())
        console.print(f"[cyan]→ Scanning {len(ports)} ports...[/cyan]")
        results = {}
        def scan(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                r = s.connect_ex((ip, port))
                s.close()
                if r == 0:
                    banner = self._banner(ip, port)
                    return port, {"service": SERVICES.get(port,"unknown"), "banner": banner, "state": "open"}
            except: pass
            return port, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            for port, info in ex.map(lambda p: scan(p), ports):
                if info: results[port] = info
        return results

    def _banner(self, ip, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3); s.connect((ip, port))
            if port in [443,8443]:
                ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=ip)
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            b = s.recv(512).decode(errors='ignore').strip(); s.close()
            return b[:150]
        except: return ""

    def ssl_check(self):
        console.print("[cyan]→ SSL/TLS vulnerability check...[/cyan]")
        findings = {"valid": False, "issues": []}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    findings["valid"] = True
                    findings["protocol"] = ssock.version()
                    findings["cipher"] = ssock.cipher()
                    findings["issuer"] = dict(x[0] for x in cert.get("issuer",()))
                    findings["expires"] = cert.get("notAfter","")
                    if "TLSv1.0" in str(ssock.version()) or "TLSv1.1" in str(ssock.version()):
                        findings["issues"].append("Outdated TLS version")
                    if "SSLv3" in str(ssock.version()):
                        findings["issues"].append("SSLv3 (POODLE vulnerable)")
        except ssl.SSLCertVerificationError as e:
            findings["issues"].append(f"Certificate error: {e}")
        except Exception as e:
            findings["issues"].append(f"Connection error: {e}")
        return findings

    def http_headers_check(self):
        console.print("[cyan]→ HTTP security headers check...[/cyan]")
        results = {"present": {}, "missing": [], "risky": {}, "score": 0}
        try:
            res = self.session.get(f"https://{self.target}", timeout=10, verify=False)
            total = len(SECURITY_HEADERS); found = 0
            for h in SECURITY_HEADERS:
                val = res.headers.get(h)
                if val:
                    results["present"][h] = val; found += 1
                else:
                    results["missing"].append(h)
            server = res.headers.get("Server","")
            powered = res.headers.get("X-Powered-By","")
            if server: results["risky"]["Server"] = server
            if powered: results["risky"]["X-Powered-By"] = powered
            results["score"] = int((found / total) * 100) if total > 0 else 0
        except Exception as e:
            results["error"] = str(e)
        return results

    def cors_check(self):
        console.print("[cyan]→ CORS misconfiguration check...[/cyan]")
        findings = []
        origins = ["https://evil.com", "null", f"https://{self.target}.evil.com"]
        for origin in origins:
            try:
                headers = {"Origin": origin}
                res = self.session.get(f"https://{self.target}", headers=headers, timeout=5, verify=False)
                acao = res.headers.get("Access-Control-Allow-Origin","")
                acac = res.headers.get("Access-Control-Allow-Credentials","")
                if acao and (acao == "*" or acao == origin):
                    findings.append({"origin": origin, "acao": acao, "credentials": acac, "severity": "HIGH" if acac == "true" else "MEDIUM"})
            except: pass
        return findings

    def tech_fingerprint(self):
        console.print("[cyan]→ Technology fingerprinting...[/cyan]")
        techs = []
        try:
            res = self.session.get(f"https://{self.target}", timeout=10, verify=False)
            body = res.text.lower(); hdrs = str(res.headers).lower()
            sigs = {"WordPress":["wp-content","wp-includes"],"React":["react","__next"],"Angular":["ng-version"],
                    "Vue.js":["vue","__vue"],"jQuery":["jquery"],"Bootstrap":["bootstrap"],
                    "Laravel":["laravel","csrf-token"],"Django":["csrfmiddlewaretoken"],
                    "Next.js":["_next/static"],"Nuxt.js":["__nuxt"],"Express":["express"],
                    "Nginx":[],"Apache":[],"Cloudflare":[]}
            for tech, kws in sigs.items():
                if tech.lower() in hdrs or any(k in body for k in kws): techs.append(tech)
            if res.headers.get("cf-ray"): techs.append("Cloudflare CDN")
        except: pass
        return list(set(techs))

    def cve_lookup(self, services):
        console.print("[cyan]→ CVE lookup for detected services...[/cyan]")
        cve_results = {}
        for port, info in services.items():
            svc = info.get("service","").lower()
            banner = info.get("banner","").lower()
            version_match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
            if version_match:
                version = version_match.group(1)
                try:
                    url = f"https://cve.circl.lu/api/search/{svc}/{version}"
                    res = self.session.get(url, timeout=10)
                    if res.status_code == 200:
                        cves = res.json()
                        if isinstance(cves, list) and cves:
                            cve_results[f"{svc}:{port}"] = [{"id": c.get("id",""), "summary": c.get("summary","")[:100]} for c in cves[:5]]
                except: pass
        return cve_results

    def run(self):
        ip = self.resolve()
        if not ip: return

        console.print(Panel(f"[bold cyan]NETWORK VULNERABILITY SCANNER — {self.target}[/bold cyan]\n[dim]Ports • SSL/TLS • Headers • CORS • CVE • Tech Stack[/dim]", border_style="cyan"))

        result = {"target": self.target, "ip": ip, "scan_time": datetime.now().isoformat()}

        ports = self.port_scan(ip)
        result["open_ports"] = ports
        if ports:
            pt = Table(title=f"Open Ports ({len(ports)})", show_header=True, header_style="bold green")
            pt.add_column("Port", style="cyan", width=8); pt.add_column("Service", style="yellow", width=15); pt.add_column("Banner", style="dim")
            for p in sorted(ports): pt.add_row(str(p), ports[p]["service"], ports[p]["banner"][:50])
            console.print(pt)

        ssl_info = self.ssl_check()
        result["ssl"] = ssl_info
        if ssl_info.get("valid"):
            console.print(f"[green]  ✔ SSL Valid — {ssl_info.get('protocol','')} — Expires: {ssl_info.get('expires','')}[/green]")
        for issue in ssl_info.get("issues",[]):
            console.print(f"[red]  ⚠ SSL Issue: {issue}[/red]")

        headers = self.http_headers_check()
        result["security_headers"] = headers
        ht = Table(title=f"Security Headers (Score: {headers.get('score',0)}%)", show_header=True, header_style="bold blue")
        ht.add_column("Header", style="cyan", width=30); ht.add_column("Status", width=10); ht.add_column("Value", style="dim")
        for h in SECURITY_HEADERS:
            if h in headers.get("present",{}):
                ht.add_row(h, "[green]✔[/green]", str(headers["present"][h])[:50])
            else:
                ht.add_row(h, "[red]✘ MISSING[/red]", "")
        for h, v in headers.get("risky",{}).items():
            ht.add_row(h, "[yellow]⚠ EXPOSED[/yellow]", v)
        console.print(ht)

        cors = self.cors_check()
        result["cors"] = cors
        if cors:
            console.print(Panel("[bold red]⚠ CORS MISCONFIGURATION DETECTED[/bold red]", border_style="red"))
            for c in cors:
                console.print(f"  [red]Origin: {c['origin']} → ACAO: {c['acao']} (Credentials: {c['credentials']})[/red]")

        techs = self.tech_fingerprint()
        result["technologies"] = techs
        if techs:
            console.print(Panel(f"[bold green]{' • '.join(techs)}[/bold green]", title="Technologies", border_style="green"))

        cves = self.cve_lookup(ports)
        result["cves"] = cves
        if cves:
            console.print(Panel("[bold red]⚠ POTENTIAL CVEs FOUND[/bold red]", border_style="red"))
            for svc, cvelist in cves.items():
                for c in cvelist: console.print(f"  [red]{svc} → {c['id']}: {c['summary']}[/red]")

        # Vulnerability score
        vuln_score = 0
        vuln_score += len(ssl_info.get("issues",[])) * 15
        vuln_score += len(headers.get("missing",[])) * 5
        vuln_score += len(cors) * 20
        vuln_score += len(cves) * 10
        vuln_score += len(headers.get("risky",{})) * 5
        vuln_score = min(vuln_score, 100)
        result["vulnerability_score"] = vuln_score
        vc = "green" if vuln_score < 30 else ("yellow" if vuln_score < 60 else "red")
        console.print(Panel(f"[{vc}]Vulnerability Score: {vuln_score}/100[/{vc}]", title="Assessment", border_style=vc))

        Config.ensure_dirs()
        fn = f"logs/netvuln_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fn, "w") as f: json.dump(result, f, indent=2, default=str)
        console.print(f"\n[green]✔ Saved: {fn}[/green]")

def main():
    console.print(Panel("[bold cyan]NETWORK VULNERABILITY SCANNER — OSINT-Hunter V3[/bold cyan]\n[dim]Ports • SSL/TLS • Headers • CORS • CVE Lookup • Tech Stack[/dim]", border_style="cyan"))
    t = input("\n  Enter target domain or IP: ").strip()
    if not t: console.print("[red]Empty![/red]"); return
    NetworkVulnScanner(t).run()

if __name__ == "__main__": main()
