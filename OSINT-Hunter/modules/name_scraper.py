#!/usr/bin/env python3

import os, json, sys, requests, re, time
from datetime import datetime
from urllib.parse import quote_plus
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
import concurrent.futures

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()

SEARCH_ENGINES = {
    "DuckDuckGo": "https://html.duckduckgo.com/html/?q={}",
    "Bing": "https://www.bing.com/search?q={}&count=30",
    "Ask": "https://www.ask.com/web?q={}",
    "Yahoo": "https://search.yahoo.com/search?p={}&n=20",
}

PEOPLE_SEARCH_DORKS = [
    '"{name}"',
    '"{name}" site:linkedin.com',
    '"{name}" site:facebook.com',
    '"{name}" site:twitter.com OR site:x.com',
    '"{name}" site:instagram.com',
    '"{name}" site:github.com',
    '"{name}" site:youtube.com',
    '"{name}" site:tiktok.com',
    '"{name}" site:reddit.com',
    '"{name}" site:medium.com',
    '"{name}" site:t.me',
    '"{name}" site:vk.com',
    '"{name}" email OR contact',
    '"{name}" filetype:pdf',
    '"{name}" resume OR cv OR portfolio',
    '"{name}" site:behance.net OR site:dribbble.com',
    '"{name}" site:kaggle.com OR site:stackoverflow.com',
]

SOCIAL_DIRECT_CHECK = {
    "GitHub": "https://github.com/search?q={}&type=users",
    "GitHub Repos": "https://github.com/search?q={}&type=repositories",
    "Reddit": "https://www.reddit.com/search/?q={}&type=user",
    "YouTube": "https://www.youtube.com/results?search_query={}",
    "npm": "https://www.npmjs.com/search?q={}",
    "PyPI": "https://pypi.org/search/?q={}",
    "Docker Hub": "https://hub.docker.com/search?q={}",
    "GitLab": "https://gitlab.com/search?search={}",
}


class NameScraper:
    def __init__(self, query):
        self.query = query.strip()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.get_random_ua()})
        proxy = Config.get_proxy_dict()
        if proxy:
            self.session.proxies = proxy
        self.all_links = []
        self.all_mentions = []
        self.profiles = []

    def _fetch(self, url, timeout=12):
        try:
            headers = {"User-Agent": Config.get_random_ua(), "Accept-Language": "en-US,en;q=0.9"}
            res = self.session.get(url, timeout=timeout, headers=headers, verify=False)
            return res
        except Exception:
            return None

    def scrape_duckduckgo(self):
        console.print("[cyan]→ Scraping DuckDuckGo...[/cyan]")
        results = []
        try:
            url = SEARCH_ENGINES["DuckDuckGo"].format(quote_plus(self.query))
            res = self._fetch(url)
            if res and res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                for r in soup.select('.result__body'):
                    title_el = r.select_one('.result__title a')
                    snippet_el = r.select_one('.result__snippet')
                    if title_el:
                        title = title_el.get_text(strip=True)
                        link = title_el.get('href', '')
                        snippet = snippet_el.get_text(strip=True) if snippet_el else ""

                        if self.query.lower() in title.lower() or self.query.lower() in snippet.lower() or self.query.lower() in link.lower():
                            results.append({
                                "source": "DuckDuckGo",
                                "title": title[:120],
                                "url": link,
                                "snippet": snippet[:200],
                                "relevance": "high" if self.query.lower() in title.lower() else "medium"
                            })
                console.print(f"[green]  ✔ Found {len(results)} results[/green]")
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")
        return results

    def scrape_bing(self):
        console.print("[cyan]→ Scraping Bing...[/cyan]")
        results = []
        try:
            url = SEARCH_ENGINES["Bing"].format(quote_plus(self.query))
            res = self._fetch(url)
            if res and res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                for li in soup.select('.b_algo'):
                    a = li.select_one('h2 a')
                    p = li.select_one('.b_caption p')
                    if a:
                        title = a.get_text(strip=True)
                        link = a.get('href', '')
                        snippet = p.get_text(strip=True) if p else ""

                        if self.query.lower() in title.lower() or self.query.lower() in snippet.lower():
                            results.append({
                                "source": "Bing",
                                "title": title[:120],
                                "url": link,
                                "snippet": snippet[:200],
                                "relevance": "high" if self.query.lower() in title.lower() else "medium"
                            })
                console.print(f"[green]  ✔ Found {len(results)} results[/green]")
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")
        return results

    def scrape_yahoo(self):
        console.print("[cyan]→ Scraping Yahoo...[/cyan]")
        results = []
        try:
            url = SEARCH_ENGINES["Yahoo"].format(quote_plus(self.query))
            res = self._fetch(url)
            if res and res.status_code == 200:
                soup = BeautifulSoup(res.text, 'html.parser')
                for div in soup.select('.algo-sr'):
                    a = div.select_one('h3 a')
                    span = div.select_one('.compText')
                    if a:
                        title = a.get_text(strip=True)
                        link = a.get('href', '')
                        snippet = span.get_text(strip=True) if span else ""

                        if self.query.lower() in title.lower() or self.query.lower() in snippet.lower():
                            results.append({
                                "source": "Yahoo",
                                "title": title[:120],
                                "url": link,
                                "snippet": snippet[:200],
                                "relevance": "high" if self.query.lower() in title.lower() else "medium"
                            })
                console.print(f"[green]  ✔ Found {len(results)} results[/green]")
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")
        return results

    def check_github_users(self):
        console.print("[cyan]→ Searching GitHub users...[/cyan]")
        results = []
        try:
            url = f"https://api.github.com/search/users?q={quote_plus(self.query)}&per_page=10"
            res = self._fetch(url)
            if res and res.status_code == 200:
                data = res.json()
                for user in data.get("items", [])[:10]:
                    profile = {
                        "source": "GitHub",
                        "type": "profile",
                        "username": user.get("login"),
                        "url": user.get("html_url"),
                        "avatar": user.get("avatar_url"),
                        "score": user.get("score", 0),
                    }
                    try:
                        detail_res = self._fetch(user.get("url", ""), timeout=5)
                        if detail_res and detail_res.status_code == 200:
                            d = detail_res.json()
                            profile["name"] = d.get("name")
                            profile["bio"] = d.get("bio")
                            profile["location"] = d.get("location")
                            profile["company"] = d.get("company")
                            profile["email"] = d.get("email")
                            profile["repos"] = d.get("public_repos")
                            profile["followers"] = d.get("followers")
                    except Exception:
                        pass
                    results.append(profile)
                console.print(f"[green]  ✔ Found {len(results)} GitHub users[/green]")
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")
        return results

    def check_github_repos(self):
        console.print("[cyan]→ Searching GitHub repositories...[/cyan]")
        results = []
        try:
            url = f"https://api.github.com/search/repositories?q={quote_plus(self.query)}&per_page=10&sort=stars"
            res = self._fetch(url)
            if res and res.status_code == 200:
                data = res.json()
                for repo in data.get("items", [])[:10]:
                    results.append({
                        "source": "GitHub",
                        "type": "repository",
                        "name": repo.get("full_name"),
                        "url": repo.get("html_url"),
                        "description": (repo.get("description") or "")[:120],
                        "stars": repo.get("stargazers_count", 0),
                        "language": repo.get("language"),
                        "owner": repo.get("owner", {}).get("login"),
                    })
                console.print(f"[green]  ✔ Found {len(results)} repositories[/green]")
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")
        return results

    def scrape_social_direct(self):
        console.print("[cyan]→ Checking social/dev platforms...[/cyan]")
        results = []
        for platform, url_template in SOCIAL_DIRECT_CHECK.items():
            if platform in ["GitHub", "GitHub Repos"]:
                continue
            try:
                url = url_template.format(quote_plus(self.query))
                res = self._fetch(url, timeout=8)
                if res and res.status_code == 200:
                    soup = BeautifulSoup(res.text, 'html.parser')
                    page_text = soup.get_text().lower()
                    if self.query.lower() in page_text:
                        links_found = []
                        for a in soup.find_all('a', href=True):
                            href = a.get('href', '')
                            text = a.get_text(strip=True)
                            if self.query.lower() in text.lower() or self.query.lower() in href.lower():
                                if href.startswith('http'):
                                    links_found.append({"text": text[:80], "url": href})
                                elif href.startswith('/'):
                                    from urllib.parse import urlparse
                                    base = urlparse(url)
                                    full = f"{base.scheme}://{base.netloc}{href}"
                                    links_found.append({"text": text[:80], "url": full})

                        if links_found:
                            results.append({
                                "platform": platform,
                                "search_url": url,
                                "matches": links_found[:10],
                                "match_count": len(links_found),
                            })
            except Exception:
                pass
        console.print(f"[green]  ✔ Found matches on {len(results)} platforms[/green]")
        return results

    def generate_dork_links(self):
        dorks = []
        for template in PEOPLE_SEARCH_DORKS:
            q = template.replace("{name}", self.query)
            dorks.append({
                "query": q,
                "url": f"https://www.google.com/search?q={quote_plus(q)}"
            })
        return dorks

    def deduplicate_links(self):
        seen = set()
        unique = []
        for item in self.all_links:
            url = item.get("url", "")
            if url and url not in seen:
                seen.add(url)
                unique.append(item)
        self.all_links = unique

    def run(self):
        console.print(Panel(
            f"[bold cyan]NAME & KEYWORD SCRAPER — '{self.query}'[/bold cyan]\n"
            f"[dim]DuckDuckGo • Bing • Yahoo • GitHub • Social Platforms • Google Dorks[/dim]",
            border_style="cyan"
        ))

        ddg = self.scrape_duckduckgo()
        self.all_links.extend(ddg)
        time.sleep(1)

        bing = self.scrape_bing()
        self.all_links.extend(bing)
        time.sleep(1)

        yahoo = self.scrape_yahoo()
        self.all_links.extend(yahoo)

        gh_users = self.check_github_users()
        self.profiles.extend(gh_users)

        gh_repos = self.check_github_repos()

        social = self.scrape_social_direct()

        dorks = self.generate_dork_links()

        self.deduplicate_links()

        if self.all_links:
            se_table = Table(
                title=f"Search Results — '{self.query}' ({len(self.all_links)} found)",
                show_header=True, header_style="bold green"
            )
            se_table.add_column("#", style="dim", width=4, justify="right")
            se_table.add_column("Source", style="cyan", width=12)
            se_table.add_column("Title", style="white", width=35)
            se_table.add_column("URL", style="yellow")
            se_table.add_column("Match", justify="center", width=6)

            for i, item in enumerate(self.all_links, 1):
                rel_color = "green" if item.get("relevance") == "high" else "yellow"
                se_table.add_row(
                    str(i),
                    item.get("source", ""),
                    item.get("title", "")[:35],
                    item.get("url", "")[:55],
                    f"[{rel_color}]{'★★★' if item.get('relevance') == 'high' else '★★'}[/{rel_color}]"
                )

            console.print(se_table)

        if gh_users:
            console.print()
            gh_table = Table(title="GitHub Users", show_header=True, header_style="bold blue")
            gh_table.add_column("Username", style="cyan", width=18)
            gh_table.add_column("Name", style="white", width=20)
            gh_table.add_column("Bio", style="dim", width=30)
            gh_table.add_column("Location", style="yellow", width=15)
            gh_table.add_column("Repos", justify="right", width=6)
            gh_table.add_column("Followers", justify="right", width=8)

            for u in gh_users:
                gh_table.add_row(
                    u.get("username", ""),
                    str(u.get("name", "") or "—"),
                    str(u.get("bio", "") or "—")[:30],
                    str(u.get("location", "") or "—"),
                    str(u.get("repos", "—")),
                    str(u.get("followers", "—")),
                )
            console.print(gh_table)

        if gh_repos:
            console.print()
            repo_table = Table(title="GitHub Repositories", show_header=True, header_style="bold green")
            repo_table.add_column("Repository", style="cyan", width=25)
            repo_table.add_column("Description", style="dim", width=35)
            repo_table.add_column("Language", style="yellow", width=10)
            repo_table.add_column("⭐", justify="right", width=6)
            repo_table.add_column("URL", style="blue")

            for r in gh_repos:
                repo_table.add_row(
                    r.get("name", ""),
                    r.get("description", "—")[:35],
                    r.get("language", "—") or "—",
                    str(r.get("stars", 0)),
                    r.get("url", "")[:45],
                )
            console.print(repo_table)

        if social:
            console.print()
            console.print(Panel("[bold cyan]Social & Dev Platform Matches[/bold cyan]", border_style="cyan"))
            for s in social:
                console.print(f"\n  [bold magenta]{s['platform']}[/bold magenta] — {s['match_count']} matches")
                for m in s.get("matches", [])[:5]:
                    console.print(f"    [blue]→[/blue] {m.get('text', '')[:50]} | [dim]{m.get('url', '')[:60]}[/dim]")

        all_urls = set()
        for item in self.all_links:
            if item.get("url"):
                all_urls.add(item["url"])
        for u in gh_users:
            if u.get("url"):
                all_urls.add(u["url"])
        for r in gh_repos:
            if r.get("url"):
                all_urls.add(r["url"])
        for s in social:
            for m in s.get("matches", []):
                if m.get("url"):
                    all_urls.add(m["url"])

        if all_urls:
            console.print()
            console.print(Panel(
                f"[bold green]All Links Found ({len(all_urls)} unique)[/bold green]",
                border_style="green"
            ))
            for i, url in enumerate(sorted(all_urls), 1):
                console.print(f"  [dim]{i:3}.[/dim] {url}")

        console.print()
        console.print("[bold cyan]Google Dork Queries:[/bold cyan]")
        for d in dorks[:10]:
            console.print(f"  [dim]{d['query']}[/dim]")
        console.print(f"  [dim]... ({len(dorks)} total dorks available)[/dim]")

        console.print(Panel(
            f"[bold]Search Results:[/bold] {len(self.all_links)}  |  "
            f"[bold]GitHub Users:[/bold] {len(gh_users)}  |  "
            f"[bold]GitHub Repos:[/bold] {len(gh_repos)}  |  "
            f"[bold]Platform Matches:[/bold] {len(social)}  |  "
            f"[bold]Total Unique URLs:[/bold] {len(all_urls)}",
            title="Scraping Summary",
            border_style="blue"
        ))

        Config.ensure_dirs()
        folder = f"results/{self.query.replace(' ', '_')}"
        os.makedirs(folder, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{folder}/name_scrape_{timestamp}.json"
        report = {
            "query": self.query,
            "scan_time": datetime.now().isoformat(),
            "search_results": self.all_links,
            "github_users": gh_users,
            "github_repos": gh_repos,
            "social_matches": social,
            "all_unique_urls": sorted(list(all_urls)),
            "dork_queries": dorks,
            "stats": {
                "total_search_results": len(self.all_links),
                "total_github_users": len(gh_users),
                "total_github_repos": len(gh_repos),
                "total_platform_matches": len(social),
                "total_unique_urls": len(all_urls),
            }
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n[green]✔ Full report saved: {filename}[/green]")

        url_list_file = f"{folder}/urls_{timestamp}.txt"
        with open(url_list_file, "w") as f:
            for url in sorted(all_urls):
                f.write(url + "\n")
        console.print(f"[green]✔ URL list saved: {url_list_file}[/green]")


def main():
    console.print(Panel(
        "[bold cyan]NAME & KEYWORD SCRAPER — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]Deep search across search engines, GitHub, social platforms[/dim]\n"
        "[dim]Finds ALL links and mentions containing your query[/dim]",
        border_style="cyan"
    ))
    query = input("\n  Enter name or keyword to search: ").strip()
    if not query:
        console.print("[red]❌ Query cannot be empty![/red]")
        return
    scraper = NameScraper(query)
    scraper.run()


if __name__ == "__main__":
    main()
