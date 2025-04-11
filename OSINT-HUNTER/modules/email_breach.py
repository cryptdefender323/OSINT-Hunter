import re
import os
import time
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from datetime import datetime
from urllib.parse import quote_plus

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

def dork_search(email, proxy=None):
    base_url = "https://www.google.com/search?q="
    queries = [
        f'"{email}" site:pastebin.com',
        f'"{email}" filetype:txt',
        f'"{email}" inurl:breach OR leaked',
        f'"{email}" site:scylla.sh',
        f'"{email}" site:raidforums.com',
        f'"{email}" site:ghostbin.com',
    ]
    dork_results = []
    console.print("\n[bold green][~][/bold green] Google Dorking for breach links...")

    for q in queries:
        url = base_url + quote_plus(q)
        try:
            res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
            soup = BeautifulSoup(res.text, 'html.parser')
            results = soup.find_all('a')
            for r in results:
                href = r.get('href')
                if "/url?q=" in href:
                    actual_link = href.split("/url?q=")[1].split("&")[0]
                    if email in actual_link:
                        dork_results.append(actual_link)
        except Exception as e:
            console.print(f"[red]Google dork error: {e}[/red]")
        time.sleep(1.5)
    return list(set(dork_results))

def pastebin_scrape(email, proxy=None):
    username = email.split("@")[0]
    pastebin_url = f"https://pastebin.com/u/{username}"
    console.print(f"[yellow][~] Scanning Pastebin: {pastebin_url}[/yellow]")
    try:
        res = requests.get(pastebin_url, headers=HEADERS, proxies=proxy, timeout=10)
        if "Pastebin is a website" in res.text or "syntax highlighting" in res.text:
            return [pastebin_url]
    except Exception as e:
        console.print(f"[red]Pastebin error: {e}[/red]")
    return []

def breach_compilation_check(email, proxy=None):
    leaks_found = []
    mirrors = [
        f"https://scylla.sh/search?q={quote_plus(email)}",
        f"https://www.exploit.in/search?q={quote_plus(email)}"
    ]
    for url in mirrors:
        try:
            res = requests.get(url, headers=HEADERS, proxies=proxy, timeout=10)
            if email in res.text:
                leaks_found.append(url)
        except:
            continue
    return leaks_found

def run(proxy=None):
    try:
        console.print("\n[bold cyan]:: Email Breach Analyzer[/bold cyan]")
        email = input("Enter target email: ").strip()

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            console.print("[red]❌ Email format is incorrect![/red]")
            return

        timestamp = datetime.now().strftime("%Y%m%d%H%M")
        os.makedirs("logs", exist_ok=True)
        filename = f"logs/email_breach_{email.replace('@', '_')}_{timestamp}.log"

        console.print(f"\n[bold blue][*]Look for data leaks for:[/bold blue] {email}")

        results = []

        dorks = dork_search(email, proxy)
        if dorks:
            console.print(f"[green][+] Dork result: {len(dorks)} found[/green]")
            results.extend(dorks)
        else:
            console.print("[yellow][-] Not found via Google dork[/yellow]")

        pastes = pastebin_scrape(email, proxy)
        if pastes:
            console.print("[green][+] Detected on Pastebin[/green]")
            results.extend(pastes)

        mirrors = breach_compilation_check(email, proxy)
        if mirrors:
            console.print("[green][+] Detected at other leak sites[/green]")
            results.extend(mirrors)

        if results:
            with open(filename, "w") as f:
                f.writelines([r + "\n" for r in results])
            console.print(f"[bold green]✓ Leak found! Saved in {filename}[/bold green]")
        else:
            console.print("[red]❌ No leaks were found for this email.[/red]")

    except KeyboardInterrupt:
        console.print("\n[red]❌ Canceled by user.[/red]")
