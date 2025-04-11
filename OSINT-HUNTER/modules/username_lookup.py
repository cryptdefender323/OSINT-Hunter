import requests
from rich.console import Console
from rich.table import Table
import os
import json
from datetime import datetime

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

def run(proxy=None):
    console.print("\n[bold cyan]:: Username Lookup ::[/bold cyan]")
    username = input("Masukkan username: ").strip()

    if not username:
        console.print("[red]❌ Username cannot be empty![/red]")
        return

    results = []
    table = Table(show_header=True, header_style="bold green")
    table.add_column("Platform", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("URL", style="yellow")

    for platform, url_template in PLATFORMS.items():
        url = url_template.format(username)
        try:
            r = requests.get(url, timeout=6, proxies=proxy)
            status = "❌ Not Found"

            if r.status_code == 200:
                if username.lower() in r.text.lower():
                    status = "[green]✔️ Found[/green]"
                else:
                    status = "[yellow]⚠️  Possible[/yellow]"
            elif r.status_code in [301, 302]:
                status = "[blue]➡️ Redirect[/blue]"

            table.add_row(platform, status, url)

            results.append({
                "platform": platform,
                "status": r.status_code,
                "url": url
            })

        except Exception as e:
            table.add_row(platform, "[red]Error[/red]", url)
            results.append({
                "platform": platform,
                "status": "ERROR",
                "url": url,
                "error": str(e)
            })

    console.print(table)

    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    out_file = f"logs/username_lookup_{username}_{timestamp}.json"

    with open(out_file, "w") as f:
        json.dump(results, f, indent=4)

    console.print(f"[green]✓ Results are saved to: {out_file}[/green]")
