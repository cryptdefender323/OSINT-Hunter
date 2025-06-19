#!/usr/bin/env python3

import re
import os
import time
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from datetime import datetime
from urllib.parse import quote_plus
import json

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
}

def is_valid_email(email):
    """Validasi format email"""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def extract_links_from_html(html, keyword, domain=None):
    """Ekstrak semua link dari HTML yang cocok dengan keyword"""
    links = []
    soup = BeautifulSoup(html, 'html.parser')
    for a in soup.find_all('a', href=True):
        href = a['href']
        if domain and domain not in href:
            continue
        if keyword.lower() in href.lower():
            links.append(href)
    return list(set(links))

def fetch_page(url, keyword, proxy=None):
    """Fetch halaman dan cari kata kunci"""
    try:
        res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
        return keyword in res.text, res.text
    except:
        return False, ""

def check_pastebin(email, proxy=None):
    username = email.split("@")[0]
    url = f"https://pastebin.com/u/{username}" 
    console.print(f"[cyan]→ Scanning Pastebin for {username}...[/cyan]")
    try:
        res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
        if "Pastebin" in res.text and "Not Found" not in res.text:
            return [url]
    except Exception as e:
        console.print(f"[red]✘ Pastebin error: {e}[/red]")
    return []

def check_scylla(email, proxy=None):
    url = f"https://scylla.sh/search?q={quote_plus(email)}"
    console.print(f"[cyan]→ Searching Scylla.sh for {email}...[/cyan]")
    try:
        res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
        return [url] if email in res.text else []
    except Exception as e:
        console.print(f"[red]✘ Scylla.sh error: {e}[/red]")
    return []

def check_ghostbin(email, proxy=None):
    url = f"https://ghostbin.com/search?q={quote_plus(email)}"
    console.print(f"[cyan]→ Searching Ghostbin for {email}...[/cyan]")
    try:
        res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
        return [url] if email in res.text else []
    except Exception as e:
        console.print(f"[red]✘ Ghostbin error: {e}[/red]")
    return []

def check_raidforums(email, proxy=None):
    url = f"https://raidforums.com/search.php?query={quote_plus(email)}"
    console.print(f"[cyan]→ Searching RaidForums for {email}...[/cyan]")
    try:
        res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
        return [url] if email in res.text else []
    except Exception as e:
        console.print(f"[red]✘ RaidForums error: {e}[/red]")
    return []

def google_dork_search(email, proxy=None):
    console.print(f"[cyan]→ Running advanced Google dork search for {email}...[/cyan]")
    queries = [
        f'intext:"{email}" site:pastebin.com',
        f'intext:"{email}" filetype:txt',
        f'intext:"{email}" inurl:breach OR leaked OR dump',
        f'intext:"{email}" site:scylla.sh',
        f'intext:"{email}" site:ghostbin.com'
    ]
    results = []

    base_url = "https://www.google.com/search?q="
    for q in queries:
        search_url = base_url + quote_plus(q)
        try:
            res = requests.get(search_url, headers=HEADERS, proxies=proxy, timeout=10)
            soup = BeautifulSoup(res.text, "html.parser")
            for a in soup.find_all("a"):
                href = a.get("href")
                if "/url?q=" in href:
                    actual_link = href.split("/url?q=")[1].split("&")[0]
                    if email in actual_link:
                        results.append(actual_link)
        except Exception as e:
            console.print(f"[red]Google dork error: {e}[/red]")
        time.sleep(2)
    return list(set(results))

def check_public_leaks(email, proxy=None):
    console.print(f"[cyan]→ Checking public breach databases for {email}...[/cyan]")
    mirrors = [
        f"https://www.exploit.in/search?q={quote_plus(email)}",
        f"https://pwndb.cynsec.com/?q={quote_plus(email)}",
        f"https://breachdirectory.p.rapidapi.com?func=check&val={quote_plus(email)}"
    ]
    found = []

    for url in mirrors:
        try:
            res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
            if email in res.text:
                found.append(url)
        except:
            continue
    return found

def save_json(data, email):
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    os.makedirs("logs", exist_ok=True)
    filename = f"logs/email_breach_{email.replace('@', '_')}_{timestamp}.json"

    with open(filename, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    console.print(f"[green]✔ Results saved to {filename}[/green]")

def run(proxy=None):
    console.rule("[bold cyan]:: EMAIL BREACH ANALYZER PRO ::[/bold cyan]", align="center")
    email = input("Enter target email address: ").strip()

    if not is_valid_email(email):
        console.print("[red]❌ Invalid email format![/red]")
        return

    result = {
        "target_email": email,
        "found_in": [],
        "leak_sources": {
            "pastebin": [],
            "scylla": [],
            "ghostbin": [],
            "raidforums": [],
            "public_leaks": [],
            "google_dorks": []
        },
        "scan_summary": {
            "total_sources": 0,
            "scan_time": datetime.now().isoformat(),
            "status": "completed"
        }
    }

    pastebin_results = check_pastebin(email, proxy)
    result["leak_sources"]["pastebin"] = pastebin_results
    result["found_in"].extend(pastebin_results)

    scylla_results = check_scylla(email, proxy)
    result["leak_sources"]["scylla"] = scylla_results
    result["found_in"].extend(scylla_results)

    ghostbin_results = check_ghostbin(email, proxy)
    result["leak_sources"]["ghostbin"] = ghostbin_results
    result["found_in"].extend(ghostbin_results)

    raidforums_results = check_raidforums(email, proxy)
    result["leak_sources"]["raidforums"] = raidforums_results
    result["found_in"].extend(raidforums_results)

    public_leak_results = check_public_leaks(email, proxy)
    result["leak_sources"]["public_leaks"] = public_leak_results
    result["found_in"].extend(public_leak_results)

    dork_results = google_dork_search(email, proxy)
    result["leak_sources"]["google_dorks"] = dork_results
    result["found_in"].extend(dork_results)

    result["found_in"] = list(set(result["found_in"]))
    result["scan_summary"]["total_sources"] = len(result["found_in"])

    table = Table(show_header=True, header_style="bold green")
    table.add_column("Source", style="cyan")
    table.add_column("Found Links", style="yellow")

    for key in result["leak_sources"]:
        val = result["leak_sources"][key]
        if val:
            table.add_row(key, "\n".join(val))
    console.print(table)

    save_json(result, email)

    if result["found_in"]:
        console.print(f"[bold green]✓ Email {email} mungkin bocor di {len(result['found_in'])} lokasi![/bold green]")
    else:
        console.print(f"[bold red]✘ Email {email} tidak ditemukan di database leak atau forum publik[/bold red]")

if __name__ == "__main__":
    run()
