#!/usr/bin/env python3

import os, json, re, sys, requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_tz
    HAS_PN = True
except ImportError:
    HAS_PN = False

console = Console()

TYPE_MAP = {0:"Fixed Line",1:"Mobile",2:"Fixed/Mobile",3:"Toll Free",4:"Premium",5:"Shared Cost",6:"VoIP",7:"Personal",8:"Pager",9:"UAN",10:"Unknown"}
VOIP_CARRIERS = ["twilio","vonage","bandwidth","plivo","sinch","nexmo","google voice","skype"]

class PhoneLookup:
    def __init__(self, number):
        self.raw = number.strip()
        self.parsed = None
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.get_random_ua()})
        p = Config.get_proxy_dict()
        if p: self.session.proxies = p

    def parse(self):
        if not HAS_PN:
            console.print("[red]phonenumbers not installed[/red]"); return False
        try:
            if not self.raw.startswith("+"): self.raw = "+" + self.raw
            self.parsed = phonenumbers.parse(self.raw)
            return phonenumbers.is_valid_number(self.parsed)
        except: return False

    def basic_info(self):
        pn = self.parsed
        t = phonenumbers.number_type(pn)
        return {
            "international": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164": phonenumbers.format_number(pn, phonenumbers.PhoneNumberFormat.E164),
            "country_code": f"+{pn.country_code}",
            "country": geocoder.description_for_number(pn, "en"),
            "carrier": carrier.name_for_number(pn, "en"),
            "timezones": list(pn_tz.time_zones_for_number(pn)),
            "number_type": TYPE_MAP.get(t, "Unknown"),
            "region": phonenumbers.region_code_for_number(pn),
            "is_valid": phonenumbers.is_valid_number(pn),
        }

    def numverify(self):
        key = Config.NUMVERIFY_API_KEY
        if not key: return {}
        console.print("[cyan]→ NumVerify API...[/cyan]")
        try:
            e = phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.E164)
            r = self.session.get(f"http://apilayer.net/api/validate?access_key={key}&number={e}&format=1", timeout=10)
            return r.json() if r.status_code == 200 else {}
        except: return {}

    def social_links(self):
        n = str(self.parsed.national_number)
        cc = str(self.parsed.country_code)
        return {"whatsapp": f"https://wa.me/{cc}{n}", "telegram": f"https://t.me/+{cc}{n}"}

    def dork_queries(self):
        fmts = {self.raw, phonenumbers.format_number(self.parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL), str(self.parsed.national_number)}
        return [{"query": f'"{f}"', "url": f'https://www.google.com/search?q="{f}"'} for f in fmts]

    def risk(self, info):
        score, factors = 0, []
        if info.get("number_type") == "VoIP":
            score += 25; factors.append("VoIP number")
        c = (info.get("carrier") or "").lower()
        if any(v in c for v in VOIP_CARRIERS):
            score += 20; factors.append(f"Virtual carrier: {info.get('carrier')}")
        if not info.get("carrier"):
            score += 10; factors.append("No carrier identified")
        return min(score, 100), factors

    def run(self):
        console.print(Panel(f"[bold cyan]PHONE LOOKUP — {self.raw}[/bold cyan]", border_style="cyan"))
        if not self.parse():
            console.print("[red]❌ Invalid phone number![/red]"); return

        info = self.basic_info()
        t = Table(title="Phone Info", show_header=False)
        t.add_column("Field", style="cyan", width=18); t.add_column("Value")
        for k,v in info.items():
            if k != "timezones": t.add_row(k.replace("_"," ").title(), str(v))
        t.add_row("Timezones", ", ".join(info.get("timezones",[])))
        console.print(t)

        nv = self.numverify()
        if nv:
            nt = Table(title="NumVerify", show_header=False)
            nt.add_column("F", style="cyan"); nt.add_column("V", style="yellow")
            for k,v in nv.items():
                if v is not None: nt.add_row(k.replace("_"," ").title(), str(v))
            console.print(nt)

        social = self.social_links()
        console.print("\n[bold cyan]Social Links:[/bold cyan]")
        for p,l in social.items(): console.print(f"  [blue]{p}:[/blue] {l}")

        dorks = self.dork_queries()
        console.print("\n[bold cyan]Google Dorks:[/bold cyan]")
        for d in dorks: console.print(f"  [dim]{d['query']}[/dim]")

        rs, rf = self.risk(info)
        rc = "green" if rs < 30 else ("yellow" if rs < 60 else "red")
        console.print(Panel(f"[{rc}]Risk: {rs}/100[/{rc}]" + ("\n" + "\n".join(f"  • {f}" for f in rf) if rf else ""), title="Risk", border_style=rc))

        Config.ensure_dirs()
        fn = f"logs/phone_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fn,"w") as f: json.dump({"info":info,"numverify":nv,"social":social,"dorks":dorks,"risk":rs,"factors":rf}, f, indent=2, default=str)
        console.print(f"[green]✔ Saved: {fn}[/green]")

def main():
    console.print(Panel("[bold cyan]PHONE LOOKUP — OSINT-Hunter V3[/bold cyan]\n[dim]Carrier • Location • Type • Risk[/dim]", border_style="cyan"))
    p = input("\n  Phone number (e.g. +6281234567890): ").strip()
    if not p: console.print("[red]❌ Empty![/red]"); return
    PhoneLookup(p).run()

if __name__ == "__main__": main()
