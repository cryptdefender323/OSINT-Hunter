#!/usr/bin/env python3

import re
import os
import time
import requests
import json
import dns.resolver
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from datetime import datetime
from urllib.parse import quote_plus
import concurrent.futures
import hashlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()


class EmailBreachAnalyzer:
    def __init__(self, email):
        self.email = email
        self.headers = {"User-Agent": Config.get_random_ua()}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        proxy = Config.get_proxy_dict()
        if proxy:
            self.session.proxies.update(proxy)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.breach_data = []

    def is_valid_email(self):
        return re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", self.email)

    def fetch_page(self, url, timeout=10, headers=None):
        try:
            h = headers if headers else self.headers
            res = self.session.get(url, timeout=timeout, headers=h)
            res.raise_for_status()
            return res
        except requests.RequestException:
            return None

    def check_hibp(self):
        console.print("[cyan]→ Checking Have I Been Pwned...[/cyan]")
        api_key = Config.HIBP_API_KEY
        if not api_key:
            console.print("[yellow]  ⚠ No HIBP API key — using public breach search[/yellow]")
            return self._check_hibp_public()

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(self.email)}?truncateResponse=false"
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "OSINT-Hunter-V3"
        }
        try:
            res = self.session.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                breaches = res.json()
                for b in breaches:
                    self.breach_data.append({
                        "source": "HIBP",
                        "breach_name": b.get("Name", "Unknown"),
                        "domain": b.get("Domain", "N/A"),
                        "breach_date": b.get("BreachDate", "N/A"),
                        "data_classes": b.get("DataClasses", []),
                        "pwn_count": b.get("PwnCount", 0),
                        "description": b.get("Description", "")[:200],
                        "is_verified": b.get("IsVerified", False),
                    })
                return breaches
            elif res.status_code == 404:
                console.print("[green]  ✔ Email not found in any known breaches (HIBP)[/green]")
                return []
            elif res.status_code == 429:
                console.print("[yellow]  ⚠ Rate limited by HIBP — try again later[/yellow]")
                return []
        except Exception as e:
            console.print(f"[red]  ✘ HIBP error: {e}[/red]")
        return []

    def _check_hibp_public(self):
        sha1_hash = hashlib.sha1(self.email.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            res = self.session.get(url, timeout=10)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    h, count = line.split(":")
                    if h == suffix:
                        return [{"source": "PwnedPasswords", "note": f"Password hash found {count} times in breaches"}]
        except Exception:
            pass
        return []

    def check_emailrep(self):
        console.print("[cyan]→ Checking EmailRep.io reputation...[/cyan]")
        url = f"https://emailrep.io/{self.email}"
        headers = {
            "User-Agent": "OSINT-Hunter-V3",
            "Key": Config.EMAILREP_API_KEY
        } if Config.EMAILREP_API_KEY else {"User-Agent": "OSINT-Hunter-V3"}

        try:
            res = self.session.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                return {
                    "reputation": data.get("reputation", "N/A"),
                    "suspicious": data.get("suspicious", False),
                    "references": data.get("references", 0),
                    "blacklisted": data.get("details", {}).get("blacklisted", False),
                    "malicious_activity": data.get("details", {}).get("malicious_activity", False),
                    "credentials_leaked": data.get("details", {}).get("credentials_leaked", False),
                    "data_breach": data.get("details", {}).get("data_breach", False),
                    "spam": data.get("details", {}).get("spam", False),
                    "profiles": data.get("details", {}).get("profiles", []),
                    "spoofable": data.get("details", {}).get("spoofable", False),
                    "domain_exists": data.get("details", {}).get("domain_exists", True),
                    "days_since_domain_creation": data.get("details", {}).get("days_since_domain_creation", 0),
                }
            elif res.status_code == 429:
                console.print("[yellow]  ⚠ EmailRep rate limit reached[/yellow]")
        except Exception as e:
            console.print(f"[red]  ✘ EmailRep error: {e}[/red]")
        return {}

    def check_hunter(self):
        console.print("[cyan]→ Checking Hunter.io email verification...[/cyan]")
        api_key = Config.HUNTER_API_KEY
        if not api_key:
            console.print("[yellow]  ⚠ No Hunter.io API key — skipping[/yellow]")
            return {}

        url = f"https://api.hunter.io/v2/email-verifier?email={self.email}&api_key={api_key}"
        try:
            res = self.session.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {})
                return {
                    "result": data.get("result", "N/A"),
                    "score": data.get("score", 0),
                    "regexp": data.get("regexp", False),
                    "gibberish": data.get("gibberish", False),
                    "disposable": data.get("disposable", False),
                    "webmail": data.get("webmail", False),
                    "mx_records": data.get("mx_records", False),
                    "smtp_server": data.get("smtp_server", False),
                    "smtp_check": data.get("smtp_check", False),
                    "accept_all": data.get("accept_all", False),
                    "sources": data.get("sources", []),
                }
        except Exception as e:
            console.print(f"[red]  ✘ Hunter.io error: {e}[/red]")
        return {}

    def check_mx_records(self):
        console.print("[cyan]→ Checking MX records...[/cyan]")
        domain = self.email.split("@")[1]
        mx_data = []
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_data.append({
                    "priority": rdata.preference,
                    "host": str(rdata.exchange).rstrip(".")
                })
        except Exception:
            mx_data.append({"error": "Could not resolve MX records"})
        return mx_data

    def check_spf_dmarc(self):
        console.print("[cyan]→ Checking SPF/DMARC records...[/cyan]")
        domain = self.email.split("@")[1]
        records = {"spf": None, "dmarc": None}

        try:
            txt_answers = self.resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt = rdata.to_text()
                if "v=spf1" in txt:
                    records["spf"] = txt
        except Exception:
            pass

        try:
            dmarc_answers = self.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_answers:
                txt = rdata.to_text()
                if "v=DMARC1" in txt:
                    records["dmarc"] = txt
        except Exception:
            pass

        return records

    def check_pastebin(self):
        return []

    def google_dork_results(self):
        console.print("[cyan]→ Generating Google dork queries...[/cyan]")
        dorks = [
            f'"{self.email}" site:pastebin.com',
            f'"{self.email}" filetype:txt',
            f'"{self.email}" inurl:leak OR breach OR dump',
            f'"{self.email}" site:github.com',
            f'"{self.email}" site:trello.com',
            f'"{self.email}" filetype:sql',
            f'"{self.email}" filetype:csv',
            f'"{self.email}" filetype:log',
        ]
        return [{"query": d, "search_url": f"https://www.google.com/search?q={quote_plus(d)}"} for d in dorks]

    def run(self):
        if not self.is_valid_email():
            console.print("[red]❌ Invalid email format![/red]")
            return

        console.print(Panel(
            f"[bold cyan]Analyzing: {self.email}[/bold cyan]",
            border_style="cyan"
        ))

        result = {
            "target_email": self.email,
            "scan_time": datetime.now().isoformat(),
            "breaches": [],
            "emailrep": {},
            "hunter_verification": {},
            "mx_records": [],
            "spf_dmarc": {},
            "pastebin": [],
            "google_dorks": [],
            "risk_score": 0,
        }

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("Running breach analysis...", total=None)

            result["breaches"] = self.check_hibp()
            result["emailrep"] = self.check_emailrep()
            result["hunter_verification"] = self.check_hunter()
            result["mx_records"] = self.check_mx_records()
            result["spf_dmarc"] = self.check_spf_dmarc()
            result["pastebin"] = self.check_pastebin()
            result["google_dorks"] = self.google_dork_results()

            progress.update(task, completed=True)

        risk = 0
        if result["breaches"]:
            risk += min(len(result["breaches"]) * 15, 50)
        emailrep = result.get("emailrep", {})
        if emailrep.get("suspicious"):
            risk += 20
        if emailrep.get("blacklisted"):
            risk += 15
        if emailrep.get("malicious_activity"):
            risk += 15
        if emailrep.get("credentials_leaked"):
            risk += 10
        if emailrep.get("data_breach"):
            risk += 10
        result["risk_score"] = min(risk, 100)

        if self.breach_data:
            breach_table = Table(title="Known Breaches", show_header=True, header_style="bold red")
            breach_table.add_column("Breach", style="cyan", width=20)
            breach_table.add_column("Domain", style="yellow")
            breach_table.add_column("Date", style="magenta")
            breach_table.add_column("Records", justify="right")
            breach_table.add_column("Data Types", style="dim")

            for b in self.breach_data:
                breach_table.add_row(
                    b["breach_name"],
                    b["domain"],
                    b["breach_date"],
                    f"{b['pwn_count']:,}",
                    ", ".join(b["data_classes"][:3])
                )
            console.print(breach_table)

        if emailrep:
            rep_table = Table(title="Email Reputation", show_header=True, header_style="bold blue")
            rep_table.add_column("Check", style="cyan")
            rep_table.add_column("Result", style="magenta")
            for key, val in emailrep.items():
                if key != "profiles":
                    color = "red" if val in [True, "suspicious"] else "green"
                    rep_table.add_row(key.replace("_", " ").title(), f"[{color}]{val}[/{color}]")
            console.print(rep_table)

        risk_color = "green" if result["risk_score"] < 30 else ("yellow" if result["risk_score"] < 60 else "red")
        console.print(Panel(
            f"[{risk_color}]Risk Score: {result['risk_score']}/100[/{risk_color}]",
            title="Risk Assessment",
            border_style=risk_color
        ))

        if result["google_dorks"]:
            console.print("\n[bold cyan]Google Dork Queries:[/bold cyan]")
            for d in result["google_dorks"]:
                console.print(f"  [dim]{d['query']}[/dim]")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        Config.ensure_dirs()
        filename = f"logs/email_breach_{self.email.replace('@', '_')}_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n[green]✔ Results saved to {filename}[/green]")

        console.print(Panel(
            f"[bold]Breaches:[/bold] {len(self.breach_data)}  |  "
            f"[bold]Risk:[/bold] [{risk_color}]{result['risk_score']}%[/{risk_color}]  |  "
            f"[bold]Reputation:[/bold] {emailrep.get('reputation', 'N/A')}",
            title="Scan Summary",
            border_style="blue"
        ))


def main():
    console.print(Panel(
        "[bold cyan]EMAIL BREACH ANALYZER — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]HIBP • EmailRep • Hunter.io • MX/SPF/DMARC • Pastebin[/dim]",
        border_style="cyan"
    ))
    email = input("\n  Enter target email address: ").strip()
    analyzer = EmailBreachAnalyzer(email)
    analyzer.run()


if __name__ == "__main__":
    main()