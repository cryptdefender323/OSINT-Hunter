#!/usr/bin/env python3

import requests
from rich.console import Console
from rich.table import Table
import os
import json
from datetime import datetime
from bs4 import BeautifulSoup
import re

console = Console()

PLATFORMS = {
    "GitHub": "https://github.com/{}",   
    "Twitter": "https://twitter.com/{}",   
    "Instagram": "https://www.instagram.com/{}/",   
    "Reddit": "https://www.reddit.com/user/{}",   
    "Pinterest": "https://www.pinterest.com/{}/",   
    "TikTok": "https://www.tiktok.com/@{}",   
    "Steam": "https://steamcommunity.com/id/{}",   
    "GitLab": "https://gitlab.com/{}",   
    "SoundCloud": "https://soundcloud.com/{}",   
    "Flickr": "https://www.flickr.com/people/{}",   
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Keybase": "https://keybase.io/{}",
    "Pastebin": "https://pastebin.com/u/{}"
}

def generate_output_folder(username):
    folder = f"results/{username}"
    os.makedirs(folder, exist_ok=True)
    return folder

def extract_profile_image(url, username, folder):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')

        if 'instagram' in url:
            meta = soup.find("meta", property="og:image")
            if meta and meta["content"]:
                img_url = meta["content"]
                img_data = requests.get(img_url).content
                with open(f"{folder}/instagram.jpg", "wb") as f:
                    f.write(img_data)
                return f"{folder}/instagram.jpg"

        elif 'tiktok' in url:
            match = re.search(r'"avatarLarger":"(.*?)"', res.text)
            if match:
                img_url = match.group(1).replace("\\u0026", "&")
                img_data = requests.get(img_url).content
                with open(f"{folder}/tiktok.jpg", "wb") as f:
                    f.write(img_data)
                return f"{folder}/tiktok.jpg"

        elif 'github' in url:
            avatar = soup.select_one('img.avatar')
            if avatar:
                img_url = avatar['src']
                img_data = requests.get(img_url).content
                with open(f"{folder}/github.png", "wb") as f:
                    f.write(img_data)
                return f"{folder}/github.png"

        return None

    except Exception as e:
        return None

def run():
    console.print("\n[bold cyan]:: USERNAME LOOKUP TOOL ::[/bold cyan]")
    query = input("Masukkan username atau kata kunci (contoh: putri): ").strip()
    
    if not query:
        console.print("[red]❌ Kata kunci tidak boleh kosong![/red]")
        return

    results = []
    table = Table(show_header=True, header_style="bold green")
    table.add_column("Platform", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("URL", style="yellow")
    table.add_column("Foto", justify="center")

    folder = generate_output_folder(query)
    
    for platform, url_template in PLATFORMS.items():
        url = url_template.format(query)
        result = {
            "platform": platform,
            "url": url,
            "status": None,
            "photo": None
        }

        try:
            res = requests.get(url, timeout=8)
            status = res.status_code
            found = False

            if status == 200:
                if query.lower() in res.text.lower():
                    found = True
                    result["status"] = "[green]✔️ Ditemukan[/green]"
                    
                    photo_path = extract_profile_image(url, query, folder)
                    result["photo"] = photo_path or "Available"
                    table.add_row(platform, result["status"], url, "📷 Ya" if photo_path else "✔️")
                else:
                    result["status"] = "[yellow]⚠️ Mungkin Tersedia[/yellow]"
                    table.add_row(platform, result["status"], url, "-")
            elif status in [301, 302]:
                result["status"] = "[blue]➡️ Redirect[/blue]"
                table.add_row(platform, result["status"], url, "-")
            else:
                result["status"] = "[red]✘ Tidak Ditemukan[/red]"
                table.add_row(platform, result["status"], url, "-")

        except Exception as e:
            result["status"] = "[red]🚫 Error[/red]"
            table.add_row(platform, result["status"], url, "-")
            result["error"] = str(e)

        results.append(result)

    console.print(table)

    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    out_file = f"{folder}/lookup_{query}_{timestamp}.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    console.print(f"[green]✓ Hasil disimpan ke: {out_file}[/green]")

if __name__ == "__main__":
    run()
