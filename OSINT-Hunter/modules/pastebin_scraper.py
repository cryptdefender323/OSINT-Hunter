#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime
import json
import os
import re
import time
import concurrent.futures
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()

SENSITIVE_KEYWORDS = [
    "password", "apikey", "api_key", "authorization", "bearer", "secret",
    "access_token", "token=", "key=", "email", "credit card",
    "cvv", "bank", "pin", "login", "root", "admin", "ssh",
    "private_key", "-----BEGIN", "aws_secret", "DATABASE_URL",
    "mysql://", "postgres://", "mongodb://", "redis://",
    "smtp", "ftp://", "-----BEGIN RSA", "AKIA",
]

PASTE_SOURCES = {
    "psbdmp.ws": {
        "search_url": "https://psbdmp.ws/api/v3/search/{}",
        "type": "api"
    },
    "GitHub Gist": {
        "search_url": "https://gist.github.com/search?q={}",
        "type": "html"
    },
    "paste.ee": {
        "search_url": "https://paste.ee/search?q={}",
        "type": "html"
    },
}

CONTENT_CATEGORIES = {
    "credentials": ["password", "login", "username", "passwd", "credential"],
    "api_keys": ["apikey", "api_key", "access_token", "secret_key", "bearer"],
    "database": ["mysql://", "postgres://", "mongodb://", "DATABASE_URL", "redis://"],
    "source_code": ["import ", "function ", "def ", "class ", "var ", "const "],
    "config_files": [".env", ".config", ".yml", ".yaml", "config.json"],
    "ssh_keys": ["-----BEGIN", "ssh-rsa", "ssh-ed25519"],
    "personal_data": ["email", "phone", "address", "ssn", "credit card", "cvv"],
    "aws_keys": ["AKIA", "aws_secret", "aws_access"],
}


def categorize_content(content):
    if not content:
        return []
    content_lower = content.lower()
    categories = []
    for cat, keywords in CONTENT_CATEGORIES.items():
        for kw in keywords:
            if kw.lower() in content_lower:
                categories.append(cat)
                break
    return categories


def extract_sensitive_data(content):
    findings = []
    if not content:
        return findings

    patterns = {
        "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "url": r"https?://[^\s<>\"']+",
        "api_key_pattern": r"(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "jwt": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "connection_string": r"(?:mysql|postgres|mongodb|redis)://[^\s]+",
    }

    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings.append({"type": name, "count": len(matches), "samples": list(set(matches))[:3]})

    return findings


def search_psbdmp(keyword, proxy=None):
    results = []
    try:
        url = PASTE_SOURCES["psbdmp.ws"]["search_url"].format(keyword)
        res = requests.get(url, headers={"User-Agent": Config.get_random_ua()}, timeout=10, proxies=proxy)
        if res.status_code == 200:
            data = res.json()
            for paste in data.get("data", [])[:20]:
                paste_id = paste.get("id", "")
                paste_url = f"https://psbdmp.ws/view/{paste_id}"
                try:
                    content_res = requests.get(paste_url, headers={"User-Agent": Config.get_random_ua()}, timeout=10, proxies=proxy)
                    soup = BeautifulSoup(content_res.text, 'html.parser')
                    content_div = soup.find("div", class_="content")
                    content = content_div.get_text(strip=False) if content_div else ""
                except Exception:
                    content = ""

                results.append({
                    "source": "psbdmp.ws",
                    "url": paste_url,
                    "keyword": keyword,
                    "content_preview": content[:300] if content else "",
                    "categories": categorize_content(content),
                    "sensitive_data": extract_sensitive_data(content),
                    "has_content": bool(content and len(content) > 10),
                })
    except Exception as e:
        console.print(f"[red]  psbdmp.ws error: {e}[/red]")
    return results


def search_github_gist(keyword, proxy=None):
    results = []
    try:
        url = f"https://gist.github.com/search?q={keyword}"
        res = requests.get(url, headers={"User-Agent": Config.get_random_ua()}, timeout=10, proxies=proxy)
        if res.status_code == 200:
            soup = BeautifulSoup(res.text, "html.parser")
            for item in soup.select(".gist-snippet")[:10]:
                link = item.select_one("a.link-overlay")
                if link:
                    gist_url = "https://gist.github.com" + link.get("href", "")
                    desc = item.select_one(".f4")
                    desc_text = desc.get_text(strip=True) if desc else ""
                    code = item.select_one(".blob-code")
                    code_text = code.get_text(strip=True) if code else ""
                    results.append({
                        "source": "GitHub Gist",
                        "url": gist_url,
                        "keyword": keyword,
                        "description": desc_text[:200],
                        "content_preview": code_text[:300],
                        "categories": categorize_content(code_text),
                        "sensitive_data": extract_sensitive_data(code_text),
                        "has_content": bool(code_text),
                    })
    except Exception as e:
        console.print(f"[red]  GitHub Gist error: {e}[/red]")
    return results


def search_all(keyword, proxy=None):
    all_results = []

    console.print(f"\n[blue]  Searching psbdmp.ws...[/blue]")
    all_results.extend(search_psbdmp(keyword, proxy))

    console.print(f"[blue]  Searching GitHub Gist...[/blue]")
    all_results.extend(search_github_gist(keyword, proxy))

    return all_results


def run():
    console.print(Panel(
        "[bold cyan]PASTEBIN & LEAK SCANNER — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]psbdmp.ws • GitHub Gist • Content Categorization • Sensitive Data Extraction[/dim]",
        border_style="cyan"
    ))

    console.print("\n  [bold]Search Mode:[/bold]")
    console.print("  [1] Use built-in sensitive keywords")
    console.print("  [2] Custom keyword / name / email / phone")

    choice = input("\n  Select (1/2): ").strip()

    if choice == "1":
        keywords = SENSITIVE_KEYWORDS[:10]
        console.print(f"[blue]  Using {len(keywords)} built-in keywords[/blue]")
    elif choice == "2":
        custom = input("  Enter keyword: ").strip()
        if not custom:
            console.print("[red]❌ Keyword cannot be empty![/red]")
            return
        keywords = [custom]
    else:
        console.print("[red]❌ Invalid choice![/red]")
        return

    proxy = Config.get_proxy_dict()
    all_results = []

    for keyword in keywords:
        console.print(f"\n[cyan]→ Searching for: '{keyword}'[/cyan]")
        found = search_all(keyword, proxy)
        all_results.extend(found)

        if found:
            table = Table(show_header=True, header_style="bold green")
            table.add_column("Source", style="cyan", width=15)
            table.add_column("URL", style="yellow")
            table.add_column("Categories", style="magenta")
            table.add_column("Content", justify="center", width=8)

            for item in found:
                cats = ", ".join(item.get("categories", [])) or "—"
                has = "[green]Yes[/green]" if item.get("has_content") else "[red]No[/red]"
                table.add_row(item["source"], item["url"][:50], cats, has)

            console.print(table)

    all_sensitive = []
    for r in all_results:
        for s in r.get("sensitive_data", []):
            all_sensitive.append(s)

    if all_sensitive:
        console.print(Panel("[bold red]⚠ SENSITIVE DATA DETECTED IN PASTES[/bold red]", border_style="red"))
        sens_table = Table(title="Sensitive Data Findings", show_header=True, header_style="bold red")
        sens_table.add_column("Type", style="cyan")
        sens_table.add_column("Count", justify="right")
        sens_table.add_column("Samples", style="dim")
        for s in all_sensitive:
            sens_table.add_row(s["type"], str(s["count"]), ", ".join(str(x)[:30] for x in s["samples"]))
        console.print(sens_table)

    with_content = sum(1 for r in all_results if r.get("has_content"))
    console.print(Panel(
        f"[bold]Total Results:[/bold] {len(all_results)}  |  "
        f"[bold]With Content:[/bold] {with_content}  |  "
        f"[bold]Keywords Searched:[/bold] {len(keywords)}  |  "
        f"[bold]Sensitive Findings:[/bold] {len(all_sensitive)}",
        title="Scan Summary",
        border_style="blue"
    ))

    if all_results:
        Config.ensure_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = f"results/pastebin_{timestamp}"
        os.makedirs(folder, exist_ok=True)
        filename = f"{folder}/leak_scan_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump({"scan_time": datetime.now().isoformat(), "keywords": keywords, "total_results": len(all_results), "results": all_results}, f, indent=2, ensure_ascii=False)
        console.print(f"[green]✔ Results saved to {filename}[/green]")


if __name__ == "__main__":
    run()
