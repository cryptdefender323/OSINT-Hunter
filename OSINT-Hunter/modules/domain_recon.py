#!/usr/bin/env python3

import requests
import json
import time
import os
import dns.resolver
import socket
import ssl
import whois
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()


class DomainRecon:
    def __init__(self, domain):
        self.domain = domain.lower().strip()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.get_random_ua()})
        proxy = Config.get_proxy_dict()
        if proxy:
            self.session.proxies = proxy

    def get_whois(self):
        console.print(f"[cyan]→ WHOIS lookup for {self.domain}[/cyan]")
        try:
            w = whois.whois(self.domain)
            data = {}
            for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date',
                        'updated_date', 'name_servers', 'status', 'emails', 'org',
                        'address', 'city', 'state', 'country']:
                val = getattr(w, key, None)
                if val:
                    if isinstance(val, list):
                        data[key] = [str(v) for v in val]
                    else:
                        data[key] = str(val)
            return data
        except Exception as e:
            console.print(f"[red]  WHOIS error: {e}[/red]")
            return {"error": str(e)}

    def get_dns_records(self):
        console.print("[cyan]→ Resolving DNS records (A, AAAA, NS, MX, TXT, CNAME, SOA)[/cyan]")
        dns_data = {}
        record_types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CNAME', 'SOA']
        for rtype in record_types:
            try:
                answers = self.resolver.resolve(self.domain, rtype)
                dns_data[rtype] = [rdata.to_text() for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                dns_data[rtype] = []
            except Exception:
                dns_data[rtype] = []
        return dns_data

    def check_security_records(self):
        console.print("[cyan]→ Checking SPF / DKIM / DMARC[/cyan]")
        records = {"spf": None, "dmarc": None, "dkim_selector": None}

        try:
            txt_answers = self.resolver.resolve(self.domain, 'TXT')
            for rdata in txt_answers:
                txt = rdata.to_text()
                if "v=spf1" in txt:
                    records["spf"] = txt
        except Exception:
            pass

        try:
            dmarc = self.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
            for rdata in dmarc:
                txt = rdata.to_text()
                if "v=DMARC1" in txt:
                    records["dmarc"] = txt
        except Exception:
            pass

        for selector in ["google", "default", "selector1", "selector2", "k1", "mail"]:
            try:
                dkim = self.resolver.resolve(f"{selector}._domainkey.{self.domain}", 'TXT')
                for rdata in dkim:
                    records["dkim_selector"] = f"{selector} → {rdata.to_text()[:80]}..."
                    break
            except Exception:
                continue

        return records

    def get_http_headers(self):
        console.print("[cyan]→ Analyzing HTTP security headers[/cyan]")
        security_headers = {}
        check_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Content-Type-Options", "X-Frame-Options",
            "X-XSS-Protection", "Referrer-Policy",
            "Permissions-Policy", "Server", "X-Powered-By"
        ]
        try:
            res = self.session.get(f"https://{self.domain}", timeout=10, verify=False)
            for h in check_headers:
                val = res.headers.get(h)
                security_headers[h] = val if val else "MISSING"
            security_headers["status_code"] = res.status_code
        except Exception as e:
            security_headers["error"] = str(e)
        return security_headers

    def get_subdomains_crtsh(self):
        console.print("[cyan]→ Enumerating subdomains via crt.sh[/cyan]")
        subdomains = set()
        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = self.session.get(url, timeout=15)
            if r.status_code == 200:
                entries = r.json()
                for entry in entries:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and '*' not in sub:
                            subdomains.add(sub)
        except Exception as e:
            console.print(f"[red]  crt.sh error: {e}[/red]")
        return list(subdomains)

    def get_subdomains_anubis(self):
        console.print("[cyan]→ Enumerating subdomains via Anubis API[/cyan]")
        try:
            url = f"https://jldc.me/anubis/subdomains/{self.domain}"
            res = self.session.get(url, timeout=10)
            if res.status_code == 200:
                return res.json()
        except Exception:
            pass
        return []

    def get_subdomains_securitytrails(self):
        api_key = Config.SECURITYTRAILS_API_KEY
        if not api_key:
            return []

        console.print("[cyan]→ Enumerating subdomains via SecurityTrails[/cyan]")
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {"APIKEY": api_key}
            res = self.session.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                subs = data.get("subdomains", [])
                return [f"{s}.{self.domain}" for s in subs]
        except Exception as e:
            console.print(f"[red]  SecurityTrails error: {e}[/red]")
        return []

    def check_subdomain_takeover(self, subdomains):
        console.print("[cyan]→ Checking for subdomain takeover...[/cyan]")
        takeover_signatures = [
            "There is no app configured at that hostname",
            "NoSuchBucket", "No such bucket",
            "The specified bucket does not exist",
            "Repository not found",
            "The thing you were looking for is no longer here",
            "Project not found",
            "Fastly error: unknown domain",
            "There isn't a GitHub Pages site here",
            "is not a registered InfinityFree",
        ]
        vulnerable = []
        for sub in subdomains[:30]:
            try:
                res = self.session.get(f"http://{sub}", timeout=5)
                for sig in takeover_signatures:
                    if sig.lower() in res.text.lower():
                        vulnerable.append({"subdomain": sub, "signature": sig})
                        break
            except Exception:
                continue
        return vulnerable

    def get_wayback_urls(self):
        console.print("[cyan]→ Pulling Wayback Machine URLs[/cyan]")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=100"
            res = self.session.get(url, timeout=15)
            if res.status_code == 200:
                raw = res.json()
                return [{"url": e[0], "timestamp": e[1], "status": e[2]} for e in raw[1:]]
        except Exception:
            pass
        return []

    def get_ssl_info(self):
        console.print(f"[cyan]→ Getting SSL certificate info[/cyan]")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                        "serialNumber": cert.get("serialNumber"),
                        "version": cert.get("version"),
                        "subjectAltName": [x[1] for x in cert.get("subjectAltName", ())],
                    }
        except Exception as e:
            return {"error": str(e)}

    def detect_technologies(self):
        console.print("[cyan]→ Fingerprinting technologies[/cyan]")
        techs = []
        try:
            res = self.session.get(f"https://{self.domain}", timeout=10, verify=False)
            headers = res.headers
            body = res.text.lower()

            tech_signatures = {
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Joomla": ["joomla", "/media/jui/"],
                "Drupal": ["drupal", "/sites/default/"],
                "Laravel": ["laravel", "csrf-token"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "React": ["react", "_reactroot", "__next"],
                "Next.js": ["__next", "_next/static"],
                "Vue.js": ["vue", "__vue"],
                "Angular": ["ng-version", "angular"],
                "jQuery": ["jquery"],
                "Bootstrap": ["bootstrap"],
                "Cloudflare": ["cloudflare"],
                "Nginx": [],
                "Apache": [],
                "IIS": [],
            }

            server = headers.get("Server", "").lower()
            powered = headers.get("X-Powered-By", "").lower()

            for tech, sigs in tech_signatures.items():
                tech_lower = tech.lower()
                if tech_lower in server or tech_lower in powered:
                    techs.append(tech)
                    continue
                for sig in sigs:
                    if sig in body:
                        techs.append(tech)
                        break

            if headers.get("cf-ray"):
                techs.append("Cloudflare CDN")
            if "x-amz" in str(headers).lower():
                techs.append("AWS")
            if "x-goog" in str(headers).lower():
                techs.append("Google Cloud")

        except Exception:
            pass
        return list(set(techs))

    def run(self):
        console.print(Panel(
            f"[bold cyan]DOMAIN RECON — {self.domain}[/bold cyan]\n"
            f"[dim]WHOIS • DNS • Subdomains • SSL • Headers • Tech Stack[/dim]",
            border_style="cyan"
        ))

        result = {
            "domain": self.domain,
            "scan_time": datetime.now().isoformat(),
            "whois": {},
            "dns_records": {},
            "security_records": {},
            "http_headers": {},
            "ssl_info": {},
            "subdomains": [],
            "subdomain_takeover": [],
            "wayback_urls": [],
            "technologies": [],
        }

        result["whois"] = self.get_whois()
        result["dns_records"] = self.get_dns_records()
        result["security_records"] = self.check_security_records()
        result["http_headers"] = self.get_http_headers()
        result["ssl_info"] = self.get_ssl_info()

        subs_crt = self.get_subdomains_crtsh()
        subs_anubis = self.get_subdomains_anubis()
        subs_st = self.get_subdomains_securitytrails()
        all_subs = list(set(subs_crt + subs_anubis + subs_st))
        result["subdomains"] = all_subs

        if all_subs:
            result["subdomain_takeover"] = self.check_subdomain_takeover(all_subs)

        result["wayback_urls"] = self.get_wayback_urls()
        result["technologies"] = self.detect_technologies()

        if result["whois"] and "error" not in result["whois"]:
            whois_table = Table(title="WHOIS Information", show_header=False)
            whois_table.add_column("Field", style="cyan", width=20)
            whois_table.add_column("Value", style="white")
            for k, v in result["whois"].items():
                whois_table.add_row(k.replace("_", " ").title(), str(v)[:100])
            console.print(whois_table)

        dns_table = Table(title="DNS Records", show_header=True, header_style="bold green")
        dns_table.add_column("Type", style="cyan", width=8)
        dns_table.add_column("Records", style="yellow")
        for rtype, records in result["dns_records"].items():
            if records:
                dns_table.add_row(rtype, "\n".join(str(r) for r in records[:5]))
        console.print(dns_table)

        sec = result["security_records"]
        sec_table = Table(title="Email Security (SPF/DKIM/DMARC)", show_header=True, header_style="bold blue")
        sec_table.add_column("Record", style="cyan")
        sec_table.add_column("Status", style="magenta")
        sec_table.add_row("SPF", f"[green]✔ {sec['spf'][:80]}...[/green]" if sec.get("spf") else "[red]✘ NOT CONFIGURED[/red]")
        sec_table.add_row("DMARC", f"[green]✔ {sec['dmarc'][:80]}...[/green]" if sec.get("dmarc") else "[red]✘ NOT CONFIGURED[/red]")
        sec_table.add_row("DKIM", f"[green]✔ {sec['dkim_selector']}[/green]" if sec.get("dkim_selector") else "[yellow]? Not found (common selectors)[/yellow]")
        console.print(sec_table)

        hdr = result["http_headers"]
        if "error" not in hdr:
            hdr_table = Table(title="HTTP Security Headers", show_header=True, header_style="bold yellow")
            hdr_table.add_column("Header", style="cyan", width=30)
            hdr_table.add_column("Value", style="magenta")
            for k, v in hdr.items():
                if k != "status_code":
                    color = "red" if v == "MISSING" else "green"
                    hdr_table.add_row(k, f"[{color}]{str(v)[:60]}[/{color}]")
            console.print(hdr_table)

        if result["technologies"]:
            tech_str = " • ".join(result["technologies"])
            console.print(Panel(f"[bold green]{tech_str}[/bold green]", title="Detected Technologies", border_style="green"))

        console.print(f"\n[bold cyan]Subdomains found: {len(all_subs)}[/bold cyan]")
        for s in all_subs[:20]:
            console.print(f"  [dim]{s}[/dim]")
        if len(all_subs) > 20:
            console.print(f"  [dim]... and {len(all_subs) - 20} more[/dim]")

        if result["subdomain_takeover"]:
            console.print(f"\n[bold red]⚠ Potential Subdomain Takeover:[/bold red]")
            for v in result["subdomain_takeover"]:
                console.print(f"  [red]→ {v['subdomain']} — {v['signature']}[/red]")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        Config.ensure_dirs()
        filename = f"logs/domain_recon_{self.domain}_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n[green]✔ Full report saved to {filename}[/green]")

        console.print(Panel(
            f"[bold]Subdomains:[/bold] {len(all_subs)}  |  "
            f"[bold]Wayback URLs:[/bold] {len(result['wayback_urls'])}  |  "
            f"[bold]Technologies:[/bold] {len(result['technologies'])}  |  "
            f"[bold]Takeover Risk:[/bold] {'[red]YES[/red]' if result['subdomain_takeover'] else '[green]NO[/green]'}",
            title="Recon Summary",
            border_style="blue"
        ))


def main():
    console.print(Panel(
        "[bold cyan]DOMAIN RECON — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]WHOIS • DNS • Subdomains • SSL • Headers • Tech Fingerprint[/dim]",
        border_style="cyan"
    ))
    domain = input("\n  Enter domain (without https): ").strip().lower()
    if "." not in domain:
        console.print("[red]Invalid domain format![/red]")
        return

    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    recon = DomainRecon(domain)
    recon.run()


if __name__ == "__main__":
    main()