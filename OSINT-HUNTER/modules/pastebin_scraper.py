import requests
from bs4 import BeautifulSoup
from rich.console import Console
from datetime import datetime
import json
import os

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0"}

KEYWORDS = ["password", "apikey", "authorization", "bearer", "secret", "access_token"]

MIRROR_SOURCES = {
    "psbdmp.ws": "https://psbdmp.ws/api/search/",
    "paste.ee": "https://paste.ee/search?q=",
    "controlc.com": "https://controlc.com/search/?q="
}

def scrape_psbdmp(keyword, proxy=None):
    urls = []
    console.print(f"[cyan]→ Scraping psbdmp.ws for: {keyword}[/cyan]")
    try:
        res = requests.get(MIRROR_SOURCES["psbdmp.ws"] + keyword, headers=HEADERS, timeout=10, proxies=proxy)
        data = res.json()
        for paste in data.get("data", []):
            urls.append("https://psbdmp.ws/view/" + paste.get("id"))
    except Exception as e:
        console.print(f"[red]psbdmp error: {e}[/red]")
    return urls

def scrape_pasteee(keyword, proxy=None):
    console.print(f"[cyan]→ Scraping paste.ee for: {keyword}[/cyan]")
    results = []
    try:
        url = MIRROR_SOURCES["paste.ee"] + keyword
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, "html.parser")
        for link in soup.find_all("a", href=True):
            if "/p/" in link['href']:
                full = "https://paste.ee" + link['href']
                results.append(full)
    except Exception as e:
        console.print(f"[red]paste.ee error: {e}[/red]")
    return results

def scrape_controlc(keyword, proxy=None):
    console.print(f"[cyan]→ Scraping controlc.com for: {keyword}[/cyan]")
    results = []
    try:
        url = MIRROR_SOURCES["controlc.com"] + keyword
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, "html.parser")
        for link in soup.find_all("a", href=True):
            if "controlc.com/" in link['href']:
                results.append(link['href'])
    except Exception as e:
        console.print(f"[red]controlc error: {e}[/red]")
    return results

def search_all_sources(keyword, proxy=None):
    all_urls = []
    all_urls.extend(scrape_psbdmp(keyword, proxy))
    all_urls.extend(scrape_pasteee(keyword, proxy))
    all_urls.extend(scrape_controlc(keyword, proxy))
    return list(set(all_urls))

def save_json(data, keyword):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/pastebin_leaks_{keyword}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    console.print(f"[green]✔ Saved to {filename}[/green]")

def run(proxy=None):
    try:
        console.print("\n[bold cyan]:: PASTEBIN SCRAPER MODULE[/bold cyan]")
        custom = input("Enter keyword to scan [ENTER for default]:").strip()
        keywords = KEYWORDS if custom == "" else [custom]

        for key in keywords:
            console.print(f"\n[blue][*] Searching for keyword: {key}[/blue]")
            found_links = search_all_sources(key, proxy)
            result = {
                "keyword": key,
                "count": len(found_links),
                "urls": found_links
            }
            console.print(f"[green]✓ Found {len(found_links)} results[/green]")
            save_json(result, key)

    except KeyboardInterrupt:
        console.print("\n[red]❌ Canceled by user(Ctrl+C)[/red]")
