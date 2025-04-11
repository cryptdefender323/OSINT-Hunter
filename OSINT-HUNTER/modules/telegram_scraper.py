import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import json
from datetime import datetime
from rich.console import Console
import os

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0"}

def dork_google(username, proxy=None):
    query = f"site:t.me @{username}"
    url = f"https://www.google.com/search?q={quote_plus(query)}"
    return extract_links(url, engine="google", proxy=proxy)

def dork_duckduckgo(username, proxy=None):
    query = f"site:t.me @{username}"
    url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
    return extract_links(url, engine="duckduckgo", proxy=proxy)

def extract_links(url, engine="google", proxy=None):
    links = []
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(r.text, "html.parser")
        a_tags = soup.find_all("a")

        for tag in a_tags:
            href = tag.get("href")
            if not href:
                continue
            if "t.me/" in href:
                if engine == "google" and "/url?q=" in href:
                    clean = href.split("/url?q=")[1].split("&")[0]
                    links.append(clean)
                elif engine == "duckduckgo":
                    links.append(href)
    except Exception as e:
        console.print(f"[red]Dork error ({engine}): {e}[/red]")
    return list(set(links))

def scan_direct_profile(username, proxy=None):
    link = f"https://t.me/{username}"
    console.print(f"[cyan]→ Check profile directly: {link}[/cyan]")
    try:
        r = requests.get(link, headers=HEADERS, timeout=10, proxies=proxy)
        if "tgme_page_title" in r.text:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("meta", property="og:title")
            desc = soup.find("meta", property="og:description")
            return {
                "username": username,
                "url": link,
                "title": title["content"] if title else "",
                "bio": desc["content"] if desc else ""
            }
    except Exception as e:
        console.print(f"[red]Failed to access direct profile: {e}[/red]")
    return None

def save_json(data, username):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/telegram_scrape_{username}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    console.print(f"[green]✔ Data saved to {filename}[/green]")

def run(proxy=None):
    console.print("\n[bold cyan]:: TELEGRAM OSINT SCRAPER MODULE[/bold cyan]")
    username = input("Enter Telegram username (without @): ").strip().lower()
    if not username:
        console.print("[red]Username cannot be empty![/red]")
        return

    links = dork_google(username, proxy)
    links += dork_duckduckgo(username, proxy)

    profiles = []

    for link in links:
        if "t.me/" in link:
            profiles.append({"url": link})

    direct = scan_direct_profile(username, proxy)
    if direct:
        profiles.append(direct)

    final_data = {
        "searched": username,
        "total_found": len(profiles),
        "profiles": profiles
    }

    save_json(final_data, username)
    console.print(f"[bold green]✓ Profiling completed{username}[/bold green]")
