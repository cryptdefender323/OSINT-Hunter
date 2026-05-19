#!/usr/bin/env python3

import requests
from urllib.parse import urlparse, quote_plus
import re
import tldextract
from bs4 import BeautifulSoup
import socket
import json
import os
import base64
import ipaddress
import time
import ssl
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()


class URLScanner:
    def __init__(self, target_url):
        self.target = target_url.strip()
        if not self.target.startswith("http"):
            self.target = "https://" + self.target
        self.signals = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.get_random_ua()})
        proxy = Config.get_proxy_dict()
        if proxy:
            self.session.proxies = proxy
        self.parsed = urlparse(self.target)

    def check_ssl(self):
        console.print("[cyan]→ Checking SSL certificate...[/cyan]")
        try:
            hostname = self.parsed.netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get("notAfter", "")
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    self.signals["ssl_valid"] = True
                    self.signals["ssl_issuer"] = issuer.get("organizationName", "Unknown")
                    self.signals["ssl_expires"] = not_after
        except ssl.SSLCertVerificationError:
            self.signals["ssl_valid"] = False
            self.signals["ssl_error"] = "Certificate verification failed"
        except Exception as e:
            self.signals["ssl_valid"] = False
            self.signals["ssl_error"] = str(e)

    def check_url_structure(self):
        console.print("[cyan]→ Analyzing URL structure...[/cyan]")
        url = self.target
        self.signals["url_length"] = len(url)
        self.signals["url_suspicious_length"] = len(url) > 75
        self.signals["has_ip_address"] = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
        self.signals["has_at_symbol"] = "@" in url
        self.signals["has_double_slash_redirect"] = "//" in url[8:]
        self.signals["subdomain_count"] = len(self.parsed.netloc.split(".")) - 2
        self.signals["has_hyphen_in_domain"] = "-" in self.parsed.netloc
        self.signals["has_suspicious_port"] = bool(re.search(r':\d{4,5}', url))

        ext = tldextract.extract(url)
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw', 'cc', 'club', 'work', 'date', 'bid']
        self.signals["suspicious_tld"] = ext.suffix in suspicious_tlds

    def check_redirect_chain(self):
        console.print("[cyan]→ Following redirect chain...[/cyan]")
        try:
            res = self.session.get(self.target, timeout=10, allow_redirects=True, verify=False)
            self.signals["redirect_count"] = len(res.history)
            self.signals["final_url"] = res.url
            self.signals["status_code"] = res.status_code
            chain = [{"url": r.url, "status": r.status_code} for r in res.history]
            self.signals["redirect_chain"] = chain
            self.signals["excessive_redirects"] = len(res.history) > 3
        except Exception as e:
            self.signals["redirect_error"] = str(e)

    def check_domain_reputation(self):
        console.print("[cyan]→ Checking domain reputation...[/cyan]")
        suspicious_hosts = [
            '000webhost', 'weebly', 'bit.ly', 'goo.gl', 'rebrand.ly',
            'tinyurl', 'cutt.ly', 'shorturl', 't.co', 'is.gd',
            'blogspot', 'wordpress.com', 'wixsite', 'netlify.app',
            'vercel.app', 'herokuapp.com', 'firebaseapp.com'
        ]
        ext = tldextract.extract(self.target)
        self.signals["domain"] = f"{ext.domain}.{ext.suffix}"
        self.signals["is_shortener"] = any(s in self.target.lower() for s in suspicious_hosts[:7])
        self.signals["is_free_hosting"] = any(s in self.target.lower() for s in suspicious_hosts[7:])

    def check_phishing_keywords(self):
        console.print("[cyan]→ Scanning for phishing keywords...[/cyan]")
        keywords = [
            'login', 'secure', 'update', 'banking', 'verify', 'signin',
            'paypal', 'amazon', 'apple', 'microsoft', 'account',
            'suspended', 'confirm', 'recover', 'unlock', 'credential',
            'authenticate', 'validation', 'security-alert'
        ]
        # Only check path and query string, not the domain itself
        parsed = urlparse(self.target)
        path_and_query = (parsed.path + "?" + parsed.query).lower()
        found = [k for k in keywords if k in path_and_query]
        self.signals["phishing_keywords"] = found
        self.signals["has_phishing_keywords"] = len(found) > 0

    def check_google_safe_browsing(self):
        api_key = Config.GSB_API_KEY
        if not api_key:
            self.signals["safe_browsing"] = "N/A (no API key)"
            return

        console.print("[cyan]→ Checking Google Safe Browsing...[/cyan]")
        url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        body = {
            "client": {"clientId": "osint-hunter", "clientVersion": "3.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": self.target}]
            }
        }
        try:
            res = self.session.post(url, json=body, timeout=10)
            data = res.json()
            self.signals["safe_browsing"] = "DANGEROUS" if "matches" in data else "SAFE"
            if "matches" in data:
                self.signals["safe_browsing_threats"] = [m.get("threatType") for m in data["matches"]]
        except Exception:
            self.signals["safe_browsing"] = "Error"

    def check_virustotal(self):
        api_key = Config.VT_API_KEY
        if not api_key:
            self.signals["virustotal"] = "N/A (no API key)"
            return

        console.print("[cyan]→ Checking VirusTotal...[/cyan]")
        url_id = base64.urlsafe_b64encode(self.target.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        try:
            res = self.session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
            if res.status_code == 200:
                stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                self.signals["vt_malicious"] = stats.get("malicious", 0)
                self.signals["vt_suspicious"] = stats.get("suspicious", 0)
                self.signals["vt_harmless"] = stats.get("harmless", 0)
                self.signals["vt_undetected"] = stats.get("undetected", 0)
            else:
                self.signals["virustotal"] = f"HTTP {res.status_code}"
        except Exception:
            self.signals["virustotal"] = "Error"

    def check_urlscan(self):
        api_key = Config.URLSCAN_API_KEY
        if not api_key:
            self.signals["urlscan"] = "N/A (no API key)"
            return

        console.print("[cyan]→ Submitting to URLScan.io...[/cyan]")
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        body = {"url": self.target, "visibility": "unlisted"}
        try:
            res = self.session.post("https://urlscan.io/api/v1/scan/", headers=headers, json=body, timeout=10)
            if res.status_code == 200:
                scan_uuid = res.json().get("uuid")
                self.signals["urlscan_uuid"] = scan_uuid
                self.signals["urlscan_result"] = f"https://urlscan.io/result/{scan_uuid}/"
            else:
                self.signals["urlscan"] = f"HTTP {res.status_code}"
        except Exception:
            self.signals["urlscan"] = "Error"

    def check_page_content(self):
        console.print("[cyan]→ Analyzing page content...[/cyan]")
        try:
            res = self.session.get(self.target, timeout=10, verify=False)
            soup = BeautifulSoup(res.content, "html.parser")
            text = soup.get_text().lower()

            self.signals["page_title"] = soup.title.string.strip() if soup.title and soup.title.string else "N/A"

            forms = soup.find_all("form")
            self.signals["form_count"] = len(forms)
            password_fields = soup.find_all("input", {"type": "password"})
            self.signals["has_password_field"] = len(password_fields) > 0
            hidden_fields = soup.find_all("input", {"type": "hidden"})
            self.signals["hidden_input_count"] = len(hidden_fields)

            external_links = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("http") and self.parsed.netloc not in href:
                    external_links.append(href)
            self.signals["external_link_count"] = len(external_links)

            sensitive_words = ['account number', 'social security', 'ssn', 'credit card',
                             'bank account', 'wire transfer', 'western union']
            found_sensitive = [w for w in sensitive_words if w in text]
            self.signals["sensitive_content_words"] = found_sensitive

            iframe_count = len(soup.find_all("iframe"))
            self.signals["iframe_count"] = iframe_count

        except Exception as e:
            self.signals["page_content_error"] = str(e)

    def calculate_risk_score(self):
        risk = 0
        if not self.signals.get("ssl_valid", True):
            risk += 15
        if self.signals.get("url_suspicious_length"):
            risk += 5
        if self.signals.get("has_ip_address"):
            risk += 15
        if self.signals.get("has_at_symbol"):
            risk += 10
        if self.signals.get("suspicious_tld"):
            risk += 10
        if self.signals.get("excessive_redirects"):
            risk += 10
        if self.signals.get("is_shortener"):
            risk += 5
        if self.signals.get("is_free_hosting"):
            risk += 5
        if self.signals.get("has_phishing_keywords"):
            risk += len(self.signals.get("phishing_keywords", [])) * 3
        if self.signals.get("safe_browsing") == "DANGEROUS":
            risk += 25
        if self.signals.get("vt_malicious", 0) > 0:
            risk += min(self.signals.get("vt_malicious", 0) * 5, 25)
        if self.signals.get("has_password_field"):
            risk += 5
        if self.signals.get("iframe_count", 0) > 2:
            risk += 5
        return min(risk, 100)

    def run(self):
        console.print(Panel(
            f"[bold cyan]URL SCANNER — {self.target}[/bold cyan]\n"
            f"[dim]SSL • Redirect • Phishing • VirusTotal • Safe Browsing • Content Analysis[/dim]",
            border_style="cyan"
        ))

        self.check_ssl()
        self.check_url_structure()
        self.check_redirect_chain()
        self.check_domain_reputation()
        self.check_phishing_keywords()
        self.check_google_safe_browsing()
        self.check_virustotal()
        self.check_urlscan()
        self.check_page_content()

        risk_score = self.calculate_risk_score()
        self.signals["risk_score"] = risk_score

        result_table = Table(title="URL Analysis Results", show_header=True, header_style="bold green")
        result_table.add_column("Check", style="cyan", width=25)
        result_table.add_column("Result", style="magenta")
        result_table.add_column("Risk", justify="center", width=8)

        checks = [
            ("SSL Valid", self.signals.get("ssl_valid", "N/A"), not self.signals.get("ssl_valid", True)),
            ("SSL Issuer", self.signals.get("ssl_issuer", "N/A"), False),
            ("URL Length", f"{self.signals.get('url_length', 0)} chars", self.signals.get("url_suspicious_length")),
            ("IP in URL", self.signals.get("has_ip_address", False), self.signals.get("has_ip_address")),
            ("Suspicious TLD", self.signals.get("suspicious_tld", False), self.signals.get("suspicious_tld")),
            ("Redirects", self.signals.get("redirect_count", 0), self.signals.get("excessive_redirects")),
            ("Final URL", str(self.signals.get("final_url", "N/A"))[:60], False),
            ("Is Shortener", self.signals.get("is_shortener", False), self.signals.get("is_shortener")),
            ("Free Hosting", self.signals.get("is_free_hosting", False), self.signals.get("is_free_hosting")),
            ("Phishing Keywords", ", ".join(self.signals.get("phishing_keywords", [])) or "None", self.signals.get("has_phishing_keywords")),
            ("Safe Browsing", self.signals.get("safe_browsing", "N/A"), self.signals.get("safe_browsing") == "DANGEROUS"),
            ("VT Malicious", self.signals.get("vt_malicious", "N/A"), self.signals.get("vt_malicious", 0) > 0),
            ("VT Suspicious", self.signals.get("vt_suspicious", "N/A"), self.signals.get("vt_suspicious", 0) > 0),
            ("Page Title", str(self.signals.get("page_title", "N/A"))[:50], False),
            ("Password Fields", self.signals.get("has_password_field", False), self.signals.get("has_password_field")),
            ("Forms", self.signals.get("form_count", 0), False),
            ("Iframes", self.signals.get("iframe_count", 0), self.signals.get("iframe_count", 0) > 2),
            ("External Links", self.signals.get("external_link_count", 0), False),
        ]

        for name, value, is_risk in checks:
            risk_icon = "[red]⚠[/red]" if is_risk else "[green]✔[/green]"
            result_table.add_row(name, str(value), risk_icon)

        console.print(result_table)

        risk_color = "green" if risk_score < 30 else ("yellow" if risk_score < 60 else "red")
        verdict = "SAFE" if risk_score < 30 else ("SUSPICIOUS" if risk_score < 60 else "DANGEROUS")
        console.print(Panel(
            f"[{risk_color}]Risk Score: {risk_score}/100 — {verdict}[/{risk_color}]",
            title="Risk Assessment",
            border_style=risk_color
        ))

        Config.ensure_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"logs/url_scan_{self.parsed.netloc}_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump({"target": self.target, "scan_time": datetime.now().isoformat(), "signals": self.signals}, f, indent=2, default=str)
        console.print(f"\n[green]✔ Report saved to {filename}[/green]")


def main():
    console.print(Panel(
        "[bold cyan]URL SCANNER — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]SSL • Phishing Detection • VirusTotal • Google Safe Browsing • Content Analysis[/dim]",
        border_style="cyan"
    ))
    url = input("\n  Enter URL to scan: ").strip()
    if not url:
        console.print("[red]❌ URL cannot be empty![/red]")
        return
    scanner = URLScanner(url)
    scanner.run()


if __name__ == "__main__":
    main()
