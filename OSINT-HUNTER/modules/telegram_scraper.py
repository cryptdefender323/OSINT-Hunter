#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
import os
import re

console = Console()

TELEGRAM_URL = "https://t.me/{}" 

def generate_output_folder(query):
    folder = f"results/telegram_{query}_{datetime.now().strftime('%Y%m%d%H%M')}"
    os.makedirs(folder, exist_ok=True)
    return folder

def extract_profile_info(username, folder):
    url = f"https://t.me/{username}"    
    try:
        res = requests.get(url, timeout=10)
        if res.status_code != 200:
            return None

        soup = BeautifulSoup(res.text, 'html.parser')
        profile = soup.find("div", class_="tgme_page_title")
        bio = soup.find("div", class_="tgme_page_description")

        name = profile.get_text(strip=True) if profile else username
        description = bio.get_text(strip=True) if bio else "No bio available"
        photo_path = extract_profile_image(res.text, folder)

        return {
            "url": url,
            "username": username,
            "name": name,
            "bio": description,
            "photo": os.path.basename(photo_path) if photo_path else None
        }

    except Exception as e:
        console.print(f"[red]Error fetching {username}: {e}[/red]")
        return None

def extract_profile_image(html, folder):
    match = re.search(r'<meta property="og:image" content="(.*?)">', html)
    if not match:
        return None

    img_url = match.group(1)
    try:
        img_data = requests.get(img_url).content
        filename = os.path.join(folder, "profile.jpg")
        with open(filename, "wb") as f:
            f.write(img_data)
        return filename
    except Exception as e:
        console.print(f"[red]Error saving image: {e}[/red]")
        return None

def dork_google(keyword):
    query = f'site:t.me "{keyword}"'
    url = f"https://www.google.com/search?q={quote_plus(query)}"
    return extract_telegram_links(url, engine="google")

def dork_duckduckgo(keyword):
    query = f'site:t.me "{keyword}"'
    url = f"https://duckduckgo.com/html/?q={quote_plus(query)}"
    return extract_telegram_links(url, engine="duckduckgo")

def extract_telegram_links(url, engine="google"):
    links = []
    try:
        res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        for a in soup.find_all("a"):
            href = a.get("href")
            if not href:
                continue

            if engine == "google" and "/url?q=" in href:
                clean = href.split("/url?q=")[1].split("&")[0]
                if "t.me/" in clean:
                    links.append(clean)

            elif engine == "duckduckgo" and "t.me/" in href:
                links.append(href)

    except Exception as e:
        console.print(f"[red]Error during search: {e}[/red]")
    return list(set(links))

def scan_profiles_by_keyword(keyword):
    console.print(f"\n[bold cyan]:: MENCARI AKUN TELEGRAM UNTUK KATA KUNCI '{keyword}' ::[/bold cyan]")
    
    folder = generate_output_folder(keyword)
    results = []

    google_results = dork_google(keyword)
    console.print(f"[green]✔ Found {len(google_results)} from Google[/green]")

    duckduckgo_results = dork_duckduckgo(keyword)
    console.print(f"[green]✔ Found {len(duckduckgo_results)} from DuckDuckGo[/green]")

    all_urls = list(set(google_results + duckduckgo_results))
    console.print(f"[cyan]→ Total unique profiles found: {len(all_urls)}[/cyan]")

    table = Table(show_header=True, header_style="bold green")
    table.add_column("Username", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("Bio", style="yellow")
    table.add_column("URL", style="blue")

    for url in all_urls:
        match = re.search(r"https?://t\.me/(\w+)", url)
        if not match:
            continue

        username = match.group(1)
        info = extract_profile_info(username, folder)

        if info:
            results.append(info)
            table.add_row(
                info["username"],
                info["name"][:30],
                info["bio"][:50],
                info["url"]
            )

    console.print(table)
    save_json(results, keyword, folder)

def search_by_phone(phone_number):
    console.print(f"\n[bold cyan]:: PENCARIAN BERDASARKAN NOMOR TELEPON '{phone_number}' ::[/bold cyan]")
    folder = generate_output_folder(phone_number.replace("+", "").replace(" ", "_"))
    results = []

    google_results = dork_google(phone_number)
    duckduckgo_results = dork_duckduckgo(phone_number)
    all_urls = list(set(google_results + duckduckgo_results))

    table = Table(show_header=True, header_style="bold green")
    table.add_column("Username", style="cyan")
    table.add_column("Name", style="magenta")
    table.add_column("Bio", style="yellow")
    table.add_column("URL", style="blue")

    for url in all_urls:
        match = re.search(r"https?://t\.me/(\w+)", url)
        if not match:
            continue

        username = match.group(1)
        info = extract_profile_info(username, folder)

        if info:
            results.append(info)
            table.add_row(
                info["username"],
                info["name"][:30],
                info["bio"][:50],
                info["url"]
            )

    console.print(table)
    save_json(results, phone_number.replace("+", "").replace(" ", "_"), folder)

def run():
    console.rule("[bold cyan]:: TELEGRAM OSINT SCRAPER ::[/bold cyan]", align="center")
    choice = input("Pilih cara pencarian:\n[1] Berdasarkan nama/kata kunci\n[2] Berdasarkan nomor telepon\nMasukkan pilihan: ").strip()

    if choice == "1":
        keyword = input("Masukkan nama/kata kunci (misal: putri): ").strip()
        if not keyword:
            console.print("[red]❌ Kata kunci tidak boleh kosong![/red]")
            return
        scan_profiles_by_keyword(keyword)

    elif choice == "2":
        phone = input("Masukkan nomor telepon (contoh: +628123456789): ").strip()
        if not phone:
            console.print("[red]❌ Nomor telepon tidak boleh kosong![/red]")
            return
        search_by_phone(phone)
    else:
        console.print("[red]❌ Pilihan tidak valid![/red]")

if __name__ == "__main__":
    run()
