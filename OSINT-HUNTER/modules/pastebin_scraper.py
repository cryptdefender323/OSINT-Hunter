#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from datetime import datetime
import json
import os
import re

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0"}

KEYWORDS = [
    "password", "apikey", "authorization", "bearer", "secret",
    "access_token", "key=", "token=", "email", "credit card", 
    "cvv", "bank", "pin", "login", "root", "admin"
]

MIRROR_SOURCES = {
    "psbdmp.ws": "https://psbdmp.ws/api/search/", 
    "paste.ee": "https://paste.ee/search?q=",
    "controlc.com": "https://controlc.com/search/?q="
}

def generate_output_folder(keyword):
    folder = f"results/pastebin_{keyword}_{datetime.now().strftime('%Y%m%d%H%M')}"
    os.makedirs(folder, exist_ok=True)
    return folder

def extract_content_psbdmp(url, proxy=None):
    try:
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, 'html.parser')
        content = soup.find("div", class_="content").get_text(strip=False)
        return content if content else None
    except:
        return None

def extract_content_pasteee(url, proxy=None):
    try:
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        match = re.search(r'<textarea.*?>(.*?)</textarea>', res.text, re.DOTALL)
        return match.group(1).strip() if match else None
    except:
        return None

def extract_content_controlc(url, proxy=None):
    try:
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, 'html.parser')
        textarea = soup.find("textarea", id="pastesecret")
        return textarea.get_text(strip=False) if textarea else None
    except:
        return None

def scrape_psbdmp(keyword, proxy=None):
    urls = []
    console.print(f"[cyan]→ Scanning psbdmp.ws for '{keyword}'[/cyan]")
    try:
        res = requests.get(MIRROR_SOURCES["psbdmp.ws"] + keyword, headers=HEADERS, timeout=10, proxies=proxy)
        data = res.json()
        for paste in data.get("data", []):
            full_url = "https://psbdmp.ws/view/"  + paste.get("id")
            content = extract_content_psbdmp(full_url, proxy)
            urls.append({
                "url": full_url,
                "source": "psbdmp.ws",
                "keyword": keyword,
                "content": content
            })
    except Exception as e:
        console.print(f"[red]✘ psbdmp.ws error: {e}[/red]")
    return urls

def scrape_pasteee(keyword, proxy=None):
    urls = []
    console.print(f"[cyan]→ Scanning paste.ee for '{keyword}'[/cyan]")
    try:
        url = MIRROR_SOURCES["paste.ee"] + keyword
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, "html.parser")

        for link in soup.find_all("a", href=True):
            if "/p/" in link['href']:
                full_url = "https://paste.ee"  + link['href']
                content = extract_content_pasteee(full_url, proxy)
                urls.append({
                    "url": full_url,
                    "source": "paste.ee",
                    "keyword": keyword,
                    "content": content
                })
    except Exception as e:
        console.print(f"[red]✘ paste.ee error: {e}[/red]")
    return urls

def scrape_controlc(keyword, proxy=None):
    urls = []
    console.print(f"[cyan]→ Scanning controlc.com for '{keyword}'[/cyan]")
    try:
        url = MIRROR_SOURCES["controlc.com"] + keyword
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, "html.parser")

        for link in soup.find_all("a", href=True):
            if "view.php?" in link['href']:
                full_url = "https://controlc.com/"  + link['href']
                content = extract_content_controlc(full_url, proxy)
                urls.append({
                    "url": full_url,
                    "source": "controlc.com",
                    "keyword": keyword,
                    "content": content
                })
    except Exception as e:
        console.print(f"[red]✘ controlc.com error: {e}[/red]")
    return urls

def search_all_sources(keyword, proxy=None):
    results = []
    results.extend(scrape_psbdmp(keyword, proxy))
    results.extend(scrape_pasteee(keyword, proxy))
    results.extend(scrape_controlc(keyword, proxy))
    return [dict(t) for t in {tuple(d.items()) for d in results}]

def save_json(data, keyword, folder):
    filename = os.path.join(folder, f"{keyword}_leaks.json")
    with open(filename, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    console.print(f"[green]✔ Saved to {filename}[/green]")

def run(proxy=None):
    console.rule("[bold cyan]:: PASTEBIN LEAK SCANNER ::[/bold cyan]", align="center")

    choice = input("Choose search method:\n[1] Use built-in sensitive keywords\n[2] Enter custom keyword/name/email/phone\nChoice: ").strip()

    if choice == "1":
        keywords = KEYWORDS
    elif choice == "2":
        custom = input("Enter your keyword: ").strip()
        if not custom:
            console.print("[red]❌ Keyword cannot be empty![/red]")
            return
        keywords = [custom]
    else:
        console.print("[red]❌ Invalid choice![/red]")
        return

    all_results = []

    for key in keywords:
        folder = generate_output_folder(key)
        console.print(f"\n[blue][*] Searching for keyword: {key}[/blue]")
        found_data = search_all_sources(key, proxy)

        table = Table(show_header=True, header_style="bold green")
        table.add_column("Source", style="cyan")
        table.add_column("URL", style="yellow")
        table.add_column("Found?", justify="center")

        for item in found_data:
            has_content = "[green]Yes[/green]" if item.get("content") and len(item["content"]) > 10 else "[red]No[/red]"
            table.add_row(
                item["source"],
                item["url"],
                has_content
            )
            all_results.append(item)

        console.print(table)

    console.print(f"\n[bold green]✓ Total leaks found: {len(all_results)}[/bold green]")
    if all_results:
        final_folder = generate_output_folder("final")
        save_json(all_results, "all", final_folder)

if __name__ == "__main__":
    run()
