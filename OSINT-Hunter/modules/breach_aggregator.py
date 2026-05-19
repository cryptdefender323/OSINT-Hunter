#!/usr/bin/env python3

import os, sys, json, hashlib, requests
from datetime import datetime
from urllib.parse import quote_plus
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()


class BreachAggregator:
    def __init__(self, query, query_type="email"):
        self.query = query.strip()
        self.query_type = query_type
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OSINT-Hunter-V3/BreachAggregator"})
        proxy = Config.get_proxy_dict()
        if proxy:
            self.session.proxies = proxy
        self.findings = []
        self.sources_used = []
        self.sources_skipped = []

    def check_hibp_breaches(self):
        source = "HIBP/breachedaccount"
        api_key = Config.HIBP_API_KEY
        if not api_key:
            self.sources_skipped.append(f"{source} (no HIBP_API_KEY)")
            return []
        if self.query_type != "email":
            self.sources_skipped.append(f"{source} (email only)")
            return []

        console.print("[cyan]→ HIBP breach lookup...[/cyan]")
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote_plus(self.query)}?truncateResponse=false"
            headers = {"hibp-api-key": api_key, "User-Agent": "OSINT-Hunter-V3"}
            res = self.session.get(url, headers=headers, timeout=15)

            if res.status_code == 200:
                self.sources_used.append(source)
                results = []
                for b in res.json():
                    entry = {
                        "source": "HIBP",
                        "type": "breach",
                        "name": b.get("Name", ""),
                        "domain": b.get("Domain", ""),
                        "date": b.get("BreachDate", ""),
                        "pwn_count": b.get("PwnCount", 0),
                        "data_classes": b.get("DataClasses", []),
                        "is_verified": b.get("IsVerified", False),
                        "is_sensitive": b.get("IsSensitive", False),
                        "is_fabricated": b.get("IsFabricated", False),
                    }
                    results.append(entry)
                    self.findings.append(entry)
                console.print(f"[red]  ⚠ {len(results)} breach(es) found[/red]")
                return results
            elif res.status_code == 404:
                self.sources_used.append(source)
                console.print("[green]  ✔ Not found in HIBP breaches[/green]")
                return []
            elif res.status_code == 429:
                self.sources_skipped.append(f"{source} (rate limited)")
                console.print("[yellow]  ⚠ HIBP rate limited[/yellow]")
                return []
            else:
                self.sources_skipped.append(f"{source} (HTTP {res.status_code})")
                return []
        except Exception as e:
            self.sources_skipped.append(f"{source} (error: {e})")
            return []

    def check_hibp_pastes(self):
        source = "HIBP/pasteaccount"
        api_key = Config.HIBP_API_KEY
        if not api_key:
            self.sources_skipped.append(f"{source} (no HIBP_API_KEY)")
            return []
        if self.query_type != "email":
            self.sources_skipped.append(f"{source} (email only)")
            return []

        console.print("[cyan]→ HIBP paste lookup...[/cyan]")
        try:
            url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote_plus(self.query)}"
            headers = {"hibp-api-key": api_key, "User-Agent": "OSINT-Hunter-V3"}
            res = self.session.get(url, headers=headers, timeout=15)

            if res.status_code == 200:
                self.sources_used.append(source)
                results = []
                for p in res.json():
                    entry = {
                        "source": "HIBP/paste",
                        "type": "paste",
                        "paste_source": p.get("Source", ""),
                        "title": p.get("Title", "Untitled"),
                        "date": p.get("Date", ""),
                        "email_count": p.get("EmailCount", 0),
                    }
                    results.append(entry)
                    self.findings.append(entry)
                console.print(f"[red]  ⚠ Found in {len(results)} paste(s)[/red]")
                return results
            elif res.status_code == 404:
                self.sources_used.append(source)
                console.print("[green]  ✔ Not found in HIBP pastes[/green]")
                return []
            elif res.status_code == 429:
                self.sources_skipped.append(f"{source} (rate limited)")
                return []
            else:
                self.sources_skipped.append(f"{source} (HTTP {res.status_code})")
                return []
        except Exception as e:
            self.sources_skipped.append(f"{source} (error: {e})")
            return []

    def check_pwned_password(self):
        source = "PwnedPasswords"
        if self.query_type != "password":
            return None

        console.print("[cyan]→ PwnedPasswords k-anonymity check...[/cyan]")
        try:
            sha1 = hashlib.sha1(self.query.encode("utf-8")).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            res = self.session.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
            if res.status_code == 200:
                self.sources_used.append(source)
                for line in res.text.splitlines():
                    h, count = line.split(":")
                    if h == suffix:
                        entry = {
                            "source": source,
                            "type": "password_breach",
                            "times_seen": int(count),
                            "note": f"Password appeared {count} times across known breach databases",
                        }
                        self.findings.append(entry)
                        console.print(f"[red]  ⚠ Password seen {count} times in breaches[/red]")
                        return entry
                console.print("[green]  ✔ Password not found in PwnedPasswords[/green]")
                return None
            else:
                self.sources_skipped.append(f"{source} (HTTP {res.status_code})")
                return None
        except Exception as e:
            self.sources_skipped.append(f"{source} (error: {e})")
            return None

    def check_leakcheck(self):
        source = "LeakCheck.io"
        api_key = os.getenv("LEAKCHECK_API_KEY", "")
        if not api_key:
            self.sources_skipped.append(f"{source} (no LEAKCHECK_API_KEY)")
            return []

        type_map = {"email": "email", "username": "username", "domain": "domain", "ip": "ip", "phone": "phone"}
        lc_type = type_map.get(self.query_type)
        if not lc_type:
            self.sources_skipped.append(f"{source} (unsupported type: {self.query_type})")
            return []

        console.print(f"[cyan]→ LeakCheck.io lookup ({lc_type})...[/cyan]")
        try:
            res = self.session.get(
                "https://leakcheck.io/api/v2/query",
                params={"key": api_key, "check": self.query, "type": lc_type},
                timeout=15
            )
            if res.status_code == 200:
                data = res.json()
                if not data.get("success"):
                    msg = data.get("message", "unknown error")
                    if "not found" in msg.lower():
                        self.sources_used.append(source)
                        console.print("[green]  ✔ Not found in LeakCheck[/green]")
                        return []
                    self.sources_skipped.append(f"{source} (API: {msg})")
                    return []

                self.sources_used.append(source)
                results = []
                for leak in data.get("result", []):
                    entry = {
                        "source": source,
                        "type": "credential_leak",
                        "leak_name": leak.get("source", {}).get("name", ""),
                        "leak_date": leak.get("source", {}).get("breach_date", ""),
                        "fields": leak.get("fields", []),
                        "has_password": "password" in [f.lower() for f in leak.get("fields", [])],
                        "has_hash": "hash" in [f.lower() for f in leak.get("fields", [])],
                    }
                    results.append(entry)
                    self.findings.append(entry)
                console.print(f"[red]  ⚠ Found in {len(results)} leak(s)[/red]")
                return results
            elif res.status_code == 401:
                self.sources_skipped.append(f"{source} (invalid API key)")
                return []
            elif res.status_code == 429:
                self.sources_skipped.append(f"{source} (rate limited)")
                return []
            else:
                self.sources_skipped.append(f"{source} (HTTP {res.status_code})")
                return []
        except Exception as e:
            self.sources_skipped.append(f"{source} (error: {e})")
            return []

    def check_intelx(self):
        source = "IntelX"
        api_key = os.getenv("INTELX_API_KEY", "")
        if not api_key:
            self.sources_skipped.append(f"{source} (no INTELX_API_KEY)")
            return []

        console.print("[cyan]→ IntelX search...[/cyan]")
        try:
            headers = {"x-key": api_key, "Content-Type": "application/json"}
            res = self.session.post(
                "https://2.intelx.io/intelligent/search",
                headers=headers,
                json={
                    "term": self.query, "buckets": [], "lookuplevel": 0,
                    "maxresults": 20, "timeout": 10, "datefrom": "", "dateto": "",
                    "sort": 4, "media": 0, "terminate": [],
                },
                timeout=15
            )
            if res.status_code != 200:
                self.sources_skipped.append(f"{source} (search HTTP {res.status_code})")
                return []

            search_id = res.json().get("id")
            if not search_id:
                self.sources_skipped.append(f"{source} (no search ID returned)")
                return []

            import time
            time.sleep(2)
            res2 = self.session.get(
                f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=20&offset=0",
                headers=headers,
                timeout=15
            )
            if res2.status_code != 200:
                self.sources_skipped.append(f"{source} (result HTTP {res2.status_code})")
                return []

            self.sources_used.append(source)
            results = []
            for r in res2.json().get("records", []):
                entry = {
                    "source": source,
                    "type": "intelx_record",
                    "name": r.get("name", ""),
                    "bucket": r.get("bucket", ""),
                    "date": r.get("date", ""),
                    "media_type": r.get("mediah", ""),
                    "size": r.get("size", 0),
                }
                results.append(entry)
                self.findings.append(entry)

            if results:
                console.print(f"[red]  ⚠ {len(results)} record(s) found on IntelX[/red]")
            else:
                console.print("[green]  ✔ Not found on IntelX[/green]")
            return results
        except Exception as e:
            self.sources_skipped.append(f"{source} (error: {e})")
            return []

    def check_dehashed(self):
        source = "DeHashed"
        api_key = os.getenv("DEHASHED_API_KEY", "")
        api_email = os.getenv("DEHASHED_EMAIL", "")
        if not api_key or not api_email:
            self.sources_skipped.append(f"{source} (no DEHASHED_API_KEY or DEHASHED_EMAIL)")
            return []

        type_map = {"email": "email", "username": "username", "ip": "ip_address", "domain": "domain"}
        field = type_map.get(self.query_type)
        if not field:
            self.sources_skipped.append(f"{source} (unsupported type: {self.query_type})")
            return []

        console.print("[cyan]→ DeHashed lookup...[/cyan]")
        try:
            res = self.session.get(
                f"https://api.dehashed.com/search?query={field}:{quote_plus(self.query)}&size=10",
                auth=(api_email, api_key),
                timeout=15
            )
            if res.status_code == 200:
                data = res.json()
                self.sources_used.append(source)
                results = []
                for entry in data.get("entries", []) or []:
                    record = {
                        "source": source,
                        "type": "dehashed_entry",
                        "database_name": entry.get("database_name", ""),
                        "email": entry.get("email", ""),
                        "username": entry.get("username", ""),
                        "hashed_password": entry.get("hashed_password", ""),
                        "has_plaintext": bool(entry.get("password")),
                        "ip_address": entry.get("ip_address", ""),
                        "name": entry.get("name", ""),
                        "vin": entry.get("vin", ""),
                        "address": entry.get("address", ""),
                        "phone": entry.get("phone", ""),
                    }
                    results.append(record)
                    self.findings.append(record)

                if results:
                    console.print(f"[red]  ⚠ {data.get('total', 0)} total entries found (showing {len(results)})[/red]")
                else:
                    console.print("[green]  ✔ Not found in DeHashed[/green]")
                return results
            elif res.status_code == 401:
                self.sources_skipped.append(f"{source} (invalid credentials)")
                return []
            elif res.status_code == 429:
                self.sources_skipped.append(f"{source} (rate limited)")
                return []
            else:
                self.sources_skipped.append(f"{source} (HTTP {res.status_code})")
                return []
        except Exception as e:
            self.sources_skipped.append(f"{source} (error: {e})")
            return []

    def _display_findings(self):
        if not self.findings:
            console.print(Panel("[green]✔ No findings across all queried sources[/green]", border_style="green"))
            return

        breaches = [f for f in self.findings if f["type"] == "breach"]
        pastes   = [f for f in self.findings if f["type"] == "paste"]
        leaks    = [f for f in self.findings if f["type"] in ("credential_leak", "dehashed_entry")]
        pwned_pw = [f for f in self.findings if f["type"] == "password_breach"]
        intelx   = [f for f in self.findings if f["type"] == "intelx_record"]

        if breaches:
            t = Table(title=f"HIBP Breaches ({len(breaches)})", header_style="bold red")
            t.add_column("Breach", style="cyan", width=22)
            t.add_column("Domain", style="yellow", width=20)
            t.add_column("Date", width=12)
            t.add_column("Records", justify="right", width=10)
            t.add_column("Data Types", style="dim")
            t.add_column("Verified", justify="center", width=8)
            for b in breaches:
                t.add_row(
                    b["name"], b["domain"], b["date"], f"{b['pwn_count']:,}",
                    ", ".join(b["data_classes"][:4]),
                    "[green]✔[/green]" if b["is_verified"] else "[yellow]?[/yellow]",
                )
            console.print(t)

        if pastes:
            t = Table(title=f"HIBP Pastes ({len(pastes)})", header_style="bold yellow")
            t.add_column("Site", style="cyan", width=15)
            t.add_column("Title", style="white", width=30)
            t.add_column("Date", width=12)
            t.add_column("Emails in paste", justify="right")
            for p in pastes:
                t.add_row(p["paste_source"], p["title"][:30], p["date"][:10], str(p["email_count"]))
            console.print(t)

        if pwned_pw:
            for p in pwned_pw:
                console.print(Panel(
                    f"[red]Password seen {p['times_seen']:,} times in breach databases[/red]",
                    title="PwnedPasswords", border_style="red"
                ))

        if leaks:
            t = Table(title=f"Credential Leaks ({len(leaks)})", header_style="bold red")
            t.add_column("Source", style="cyan", width=15)
            t.add_column("Database", style="yellow", width=25)
            t.add_column("Date", width=12)
            t.add_column("Has Password", justify="center", width=13)
            t.add_column("Has Hash", justify="center", width=9)
            for l in leaks:
                db = l.get("leak_name") or l.get("database_name", "")
                date = l.get("leak_date", "") or ""
                has_pw = l.get("has_plaintext") or l.get("has_password", False)
                has_hash = l.get("has_hash", False)
                t.add_row(
                    l["source"], db[:25], str(date)[:10],
                    "[red]YES[/red]" if has_pw else "[green]no[/green]",
                    "[yellow]YES[/yellow]" if has_hash else "[green]no[/green]",
                )
            console.print(t)

        if intelx:
            t = Table(title=f"IntelX Records ({len(intelx)})", header_style="bold magenta")
            t.add_column("Name", style="cyan", width=35)
            t.add_column("Bucket", style="yellow", width=15)
            t.add_column("Date", width=12)
            t.add_column("Size", justify="right", width=8)
            for r in intelx:
                t.add_row(r["name"][:35], r["bucket"], str(r["date"])[:10], str(r["size"]))
            console.print(t)

    def _display_source_status(self):
        t = Table(title="Source Status", header_style="bold blue", show_header=True)
        t.add_column("Source", style="cyan")
        t.add_column("Status")
        for s in self.sources_used:
            t.add_row(s, "[green]✔ queried[/green]")
        for s in self.sources_skipped:
            t.add_row(s, "[yellow]⚠ skipped[/yellow]")
        console.print(t)

    def run(self):
        console.print(Panel(
            f"[bold cyan]BREACH AGGREGATOR — {self.query}[/bold cyan]\n"
            f"[dim]Type: {self.query_type} | Sources: HIBP • PwnedPasswords • LeakCheck • IntelX • DeHashed[/dim]\n"
            f"[dim]API-only — no HTML scraping — no false positives[/dim]",
            border_style="cyan"
        ))

        if self.query_type == "email":
            self.check_hibp_breaches()
            self.check_hibp_pastes()
            self.check_leakcheck()
            self.check_dehashed()
            self.check_intelx()
        elif self.query_type == "password":
            self.check_pwned_password()
        elif self.query_type in ("username", "domain", "ip"):
            self.check_leakcheck()
            self.check_dehashed()
            self.check_intelx()

        self._display_findings()
        self._display_source_status()

        score = 0
        score += len([f for f in self.findings if f["type"] == "breach"]) * 15
        score += len([f for f in self.findings if f["type"] == "paste"]) * 5
        score += len([f for f in self.findings if f["type"] in ("credential_leak", "dehashed_entry")]) * 20
        score += len([f for f in self.findings if f["type"] == "password_breach"]) * 25
        score += len([f for f in self.findings if f["type"] == "intelx_record"]) * 10
        score = min(score, 100)

        color = "green" if score < 30 else ("yellow" if score < 60 else "red")
        console.print(Panel(
            f"[{color}]Exposure Score: {score}/100[/{color}]\n"
            f"[bold]Total findings:[/bold] {len(self.findings)}  |  "
            f"[bold]Sources queried:[/bold] {len(self.sources_used)}  |  "
            f"[bold]Sources skipped:[/bold] {len(self.sources_skipped)}",
            title="Assessment",
            border_style=color
        ))

        Config.ensure_dirs()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = f"logs/breach_{self.query_type}_{ts}.json"
        with open(fn, "w") as f:
            json.dump({
                "query": self.query,
                "query_type": self.query_type,
                "scan_time": datetime.now().isoformat(),
                "sources_used": self.sources_used,
                "sources_skipped": self.sources_skipped,
                "findings": self.findings,
                "exposure_score": score,
            }, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n[green]✔ Saved: {fn}[/green]")


def main():
    console.print(Panel(
        "[bold cyan]BREACH AGGREGATOR — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]HIBP • PwnedPasswords • LeakCheck • IntelX • DeHashed[/dim]\n"
        "[dim]API-only results — no scraping — no false positives[/dim]",
        border_style="cyan"
    ))

    console.print("\n  [bold]Query type:[/bold]")
    console.print("  [1] Email address")
    console.print("  [2] Username")
    console.print("  [3] Domain")
    console.print("  [4] IP address")
    console.print("  [5] Password (check if leaked)")

    c = input("\n  Select (1-5): ").strip()
    type_map = {"1": "email", "2": "username", "3": "domain", "4": "ip", "5": "password"}
    qt = type_map.get(c)
    if not qt:
        console.print("[red]Invalid choice![/red]")
        return

    q = input(f"  Enter {qt}: ").strip()
    if not q:
        console.print("[red]Empty input![/red]")
        return

    BreachAggregator(q, qt).run()


if __name__ == "__main__":
    main()
