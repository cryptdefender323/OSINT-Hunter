#!/usr/bin/env python3

import os, sys, json, requests, time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()


class UsernameOSINT:
    def __init__(self, username):
        self.username = username.strip().lstrip("@")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "OSINT-Hunter-V3/UsernameOSINT"})
        proxy = Config.get_proxy_dict()
        if proxy:
            self.session.proxies = proxy
        self.profiles = {}
        self.sources_skipped = []

    def _get(self, url, headers=None, timeout=10):
        try:
            h = {"User-Agent": "OSINT-Hunter-V3/UsernameOSINT"}
            if headers:
                h.update(headers)
            return self.session.get(url, headers=h, timeout=timeout)
        except Exception:
            return None

    def scan_github(self):
        res = self._get(f"https://api.github.com/users/{self.username}")
        if not res or res.status_code == 404:
            return None
        if res.status_code == 403:
            self.sources_skipped.append("GitHub (rate limited)")
            return None
        if res.status_code != 200:
            self.sources_skipped.append(f"GitHub (HTTP {res.status_code})")
            return None

        d = res.json()
        if d.get("login", "").lower() != self.username.lower():
            return None

        profile = {
            "found": True,
            "url": d.get("html_url", ""),
            "name": d.get("name", ""),
            "bio": d.get("bio", ""),
            "company": d.get("company", ""),
            "location": d.get("location", ""),
            "email": d.get("email", ""),
            "blog": d.get("blog", ""),
            "twitter_username": d.get("twitter_username", ""),
            "public_repos": d.get("public_repos", 0),
            "public_gists": d.get("public_gists", 0),
            "followers": d.get("followers", 0),
            "following": d.get("following", 0),
            "created_at": d.get("created_at", ""),
            "updated_at": d.get("updated_at", ""),
            "hireable": d.get("hireable"),
            "avatar_url": d.get("avatar_url", ""),
            "type": d.get("type", ""),
        }

        repos_res = self._get(f"https://api.github.com/users/{self.username}/repos?sort=updated&per_page=5")
        if repos_res and repos_res.status_code == 200:
            profile["recent_repos"] = [
                {
                    "name": r["name"],
                    "description": (r.get("description") or "")[:80],
                    "language": r.get("language", ""),
                    "stars": r.get("stargazers_count", 0),
                    "forks": r.get("forks_count", 0),
                    "url": r.get("html_url", ""),
                }
                for r in repos_res.json()[:5]
            ]

        events_res = self._get(f"https://api.github.com/users/{self.username}/events/public?per_page=5")
        if events_res and events_res.status_code == 200:
            profile["recent_events"] = [
                {
                    "type": e.get("type", ""),
                    "repo": e.get("repo", {}).get("name", ""),
                    "date": e.get("created_at", ""),
                }
                for e in events_res.json()[:5]
            ]

        self.profiles["GitHub"] = profile
        return profile

    def scan_reddit(self):
        res = self._get(
            f"https://www.reddit.com/user/{self.username}/about.json",
            headers={"User-Agent": "OSINT-Hunter-V3 (by /u/osinthunter)"}
        )
        if not res or res.status_code == 404:
            return None
        if res.status_code != 200:
            self.sources_skipped.append(f"Reddit (HTTP {res.status_code})")
            return None

        data = res.json()
        if data.get("error") == 404:
            return None

        d = data.get("data", {})
        if d.get("name", "").lower() != self.username.lower():
            return None

        profile = {
            "found": True,
            "url": f"https://www.reddit.com/user/{d.get('name', '')}",
            "name": d.get("name", ""),
            "link_karma": d.get("link_karma", 0),
            "comment_karma": d.get("comment_karma", 0),
            "total_karma": d.get("total_karma", 0),
            "created_utc": datetime.utcfromtimestamp(d.get("created_utc", 0)).isoformat() if d.get("created_utc") else "",
            "is_gold": d.get("is_gold", False),
            "is_mod": d.get("is_mod", False),
            "has_verified_email": d.get("has_verified_email", False),
            "is_employee": d.get("is_employee", False),
            "avatar_url": d.get("icon_img", "").split("?")[0],
        }

        self.profiles["Reddit"] = profile
        return profile

    def scan_twitter(self):
        bearer = os.getenv("TWITTER_BEARER_TOKEN", "")
        if not bearer:
            self.sources_skipped.append("Twitter/X (no TWITTER_BEARER_TOKEN)")
            return None

        res = self._get(
            f"https://api.twitter.com/2/users/by/username/{self.username}"
            "?user.fields=name,description,location,created_at,public_metrics,verified,profile_image_url,url,entities",
            headers={"Authorization": f"Bearer {bearer}"}
        )
        if not res:
            self.sources_skipped.append("Twitter/X (connection error)")
            return None
        if res.status_code == 404 or (res.status_code == 200 and res.json().get("errors")):
            return None
        if res.status_code == 401:
            self.sources_skipped.append("Twitter/X (invalid bearer token)")
            return None
        if res.status_code != 200:
            self.sources_skipped.append(f"Twitter/X (HTTP {res.status_code})")
            return None

        d = res.json().get("data", {})
        if not d:
            return None

        metrics = d.get("public_metrics", {})
        profile = {
            "found": True,
            "url": f"https://x.com/{self.username}",
            "id": d.get("id", ""),
            "name": d.get("name", ""),
            "description": d.get("description", ""),
            "location": d.get("location", ""),
            "created_at": d.get("created_at", ""),
            "verified": d.get("verified", False),
            "followers_count": metrics.get("followers_count", 0),
            "following_count": metrics.get("following_count", 0),
            "tweet_count": metrics.get("tweet_count", 0),
            "listed_count": metrics.get("listed_count", 0),
            "profile_image_url": d.get("profile_image_url", ""),
        }

        self.profiles["Twitter/X"] = profile
        return profile

    def scan_mastodon(self):
        res = self._get(f"https://mastodon.social/api/v1/accounts/lookup?acct={self.username}")
        if not res or res.status_code == 404:
            return None
        if res.status_code != 200:
            self.sources_skipped.append(f"Mastodon (HTTP {res.status_code})")
            return None

        d = res.json()
        if d.get("username", "").lower() != self.username.lower():
            return None

        profile = {
            "found": True,
            "url": d.get("url", ""),
            "display_name": d.get("display_name", ""),
            "note": d.get("note", "")[:200],
            "followers_count": d.get("followers_count", 0),
            "following_count": d.get("following_count", 0),
            "statuses_count": d.get("statuses_count", 0),
            "created_at": d.get("created_at", ""),
            "bot": d.get("bot", False),
            "locked": d.get("locked", False),
            "avatar": d.get("avatar", ""),
        }

        self.profiles["Mastodon"] = profile
        return profile

    def scan_keybase(self):
        res = self._get(f"https://keybase.io/_/api/1.0/user/lookup.json?username={self.username}")
        if not res or res.status_code != 200:
            self.sources_skipped.append(f"Keybase (HTTP {res.status_code if res else 'no response'})")
            return None

        data = res.json()
        if data.get("status", {}).get("code") != 0:
            return None

        them = data.get("them")
        if not them:
            return None

        basics = them.get("basics", {})
        if basics.get("username", "").lower() != self.username.lower():
            return None

        proofs = them.get("proofs_summary", {}).get("all", [])
        profile = {
            "found": True,
            "url": f"https://keybase.io/{self.username}",
            "username": basics.get("username", ""),
            "full_name": them.get("profile", {}).get("full_name", ""),
            "location": them.get("profile", {}).get("location", ""),
            "bio": them.get("profile", {}).get("bio", ""),
            "ctime": datetime.utcfromtimestamp(basics.get("ctime", 0)).isoformat() if basics.get("ctime") else "",
            "identity_proofs": [
                {
                    "service": p.get("proof_type", ""),
                    "username": p.get("nametag", ""),
                    "url": p.get("service_url", ""),
                    "state": p.get("state", 0),  # 1 = verified
                }
                for p in proofs
            ],
        }

        self.profiles["Keybase"] = profile
        return profile

    def scan_hackernews(self):
        res = self._get(f"https://hacker-news.firebaseio.com/v0/user/{self.username}.json")
        if not res or res.status_code != 200:
            return None

        d = res.json()
        if not d:
            return None

        profile = {
            "found": True,
            "url": f"https://news.ycombinator.com/user?id={self.username}",
            "id": d.get("id", ""),
            "karma": d.get("karma", 0),
            "about": d.get("about", "")[:200],
            "created": datetime.utcfromtimestamp(d.get("created", 0)).isoformat() if d.get("created") else "",
            "submitted_count": len(d.get("submitted", [])),
        }

        self.profiles["HackerNews"] = profile
        return profile

    def scan_devto(self):
        res = self._get(f"https://dev.to/api/users/by_username?url={self.username}")
        if not res or res.status_code == 404:
            return None
        if res.status_code != 200:
            self.sources_skipped.append(f"Dev.to (HTTP {res.status_code})")
            return None

        d = res.json()
        if d.get("username", "").lower() != self.username.lower():
            return None

        profile = {
            "found": True,
            "url": f"https://dev.to/{self.username}",
            "name": d.get("name", ""),
            "summary": d.get("summary", "")[:200],
            "location": d.get("location", ""),
            "joined_at": d.get("joined_at", ""),
            "twitter_username": d.get("twitter_username", ""),
            "github_username": d.get("github_username", ""),
            "website_url": d.get("website_url", ""),
            "profile_image": d.get("profile_image", ""),
        }

        self.profiles["Dev.to"] = profile
        return profile

    def scan_npm(self):
        res = self._get(f"https://registry.npmjs.org/-/v1/search?text=author:{self.username}&size=5")
        if not res or res.status_code != 200:
            return None

        data = res.json()
        objects = data.get("objects", [])
        authored = [
            o for o in objects
            if o.get("package", {}).get("author", {}).get("name", "").lower() == self.username.lower()
            or o.get("package", {}).get("publisher", {}).get("username", "").lower() == self.username.lower()
        ]

        if not authored:
            return None

        profile = {
            "found": True,
            "url": f"https://www.npmjs.com/~{self.username}",
            "package_count": len(authored),
            "packages": [
                {
                    "name": o["package"]["name"],
                    "description": o["package"].get("description", "")[:80],
                    "version": o["package"].get("version", ""),
                    "date": o["package"].get("date", ""),
                    "url": f"https://www.npmjs.com/package/{o['package']['name']}",
                }
                for o in authored[:5]
            ],
        }

        self.profiles["npm"] = profile
        return profile

    def scan_pypi(self):
        res2 = self._get(f"https://pypi.org/user/{self.username}/")
        if not res2 or res2.status_code == 404:
            return None
        if res2.status_code != 200:
            return None

        from html.parser import HTMLParser

        class PyPIParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.packages = []
                self._in_package = False
                self._current = {}

            def handle_starttag(self, tag, attrs):
                attrs_dict = dict(attrs)
                if tag == "a" and "/project/" in attrs_dict.get("href", ""):
                    href = attrs_dict["href"]
                    pkg_name = href.strip("/").split("/")[-1]
                    if pkg_name:
                        self._current = {"name": pkg_name, "url": f"https://pypi.org/project/{pkg_name}/"}
                        self._in_package = True

            def handle_endtag(self, tag):
                if tag == "a" and self._in_package and self._current:
                    self.packages.append(self._current)
                    self._current = {}
                    self._in_package = False

        parser = PyPIParser()
        parser.feed(res2.text)
        packages = list({p["name"]: p for p in parser.packages}.values())[:10]

        if not packages:
            return None

        profile = {
            "found": True,
            "url": f"https://pypi.org/user/{self.username}/",
            "package_count": len(packages),
            "packages": packages[:5],
        }

        self.profiles["PyPI"] = profile
        return profile

    def correlate(self):
        emails, locations, names, linked_accounts = set(), set(), set(), []

        for platform, data in self.profiles.items():
            if not isinstance(data, dict):
                continue
            if data.get("email"):
                emails.add(data["email"])
            if data.get("location"):
                locations.add(data["location"])
            if data.get("name"):
                names.add(data["name"])
            if data.get("twitter_username"):
                linked_accounts.append({"platform": "Twitter/X", "username": data["twitter_username"], "found_via": platform})
            if data.get("github_username"):
                linked_accounts.append({"platform": "GitHub", "username": data["github_username"], "found_via": platform})
            for proof in data.get("identity_proofs", []):
                if proof.get("state") == 1:  # verified
                    linked_accounts.append({
                        "platform": proof["service"],
                        "username": proof["username"],
                        "url": proof["url"],
                        "verified": True,
                        "found_via": "Keybase",
                    })

        return {
            "platforms_found": list(self.profiles.keys()),
            "total_found": len(self.profiles),
            "emails": list(emails),
            "locations": list(locations),
            "names": list(names),
            "linked_accounts": linked_accounts,
        }

    def run(self):
        console.print(Panel(
            f"[bold cyan]USERNAME OSINT — @{self.username}[/bold cyan]\n"
            f"[dim]GitHub • Reddit • Twitter/X • Mastodon • Keybase • HackerNews • Dev.to • npm • PyPI[/dim]\n"
            f"[dim]Official APIs only — exact username matching — no false positives[/dim]",
            border_style="cyan"
        ))

        scanners = [
            ("GitHub",     self.scan_github),
            ("Reddit",     self.scan_reddit),
            ("Twitter/X",  self.scan_twitter),
            ("Mastodon",   self.scan_mastodon),
            ("Keybase",    self.scan_keybase),
            ("HackerNews", self.scan_hackernews),
            ("Dev.to",     self.scan_devto),
            ("npm",        self.scan_npm),
            ("PyPI",       self.scan_pypi),
        ]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=len(scanners))
            for name, fn in scanners:
                progress.update(task, description=f"Checking {name}...")
                fn()
                progress.update(task, advance=1)
                time.sleep(0.3)

        for platform, data in self.profiles.items():
            if not data or not data.get("found"):
                continue

            t = Table(title=f"[bold]{platform}[/bold]", show_header=False, border_style="cyan")
            t.add_column("Field", style="cyan", width=20)
            t.add_column("Value", style="white")

            skip_keys = {"found", "avatar_url", "avatar", "profile_image", "profile_image_url",
                         "recent_repos", "recent_events", "identity_proofs", "packages"}
            for k, v in data.items():
                if k in skip_keys or not v:
                    continue
                t.add_row(k.replace("_", " ").title(), str(v)[:100])
            console.print(t)

            if platform == "GitHub" and data.get("recent_repos"):
                rt = Table(title="Recent Repos", show_header=True, header_style="bold green")
                rt.add_column("Name", style="cyan", width=25)
                rt.add_column("Language", style="yellow", width=12)
                rt.add_column("⭐", justify="right", width=6)
                rt.add_column("Description", style="dim")
                for r in data["recent_repos"]:
                    rt.add_row(r["name"], r.get("language") or "—", str(r["stars"]), r["description"][:50])
                console.print(rt)

            if platform == "Keybase" and data.get("identity_proofs"):
                pt = Table(title="Identity Proofs (Keybase-verified)", show_header=True, header_style="bold green")
                pt.add_column("Service", style="cyan", width=15)
                pt.add_column("Username", style="yellow", width=20)
                pt.add_column("Verified", justify="center", width=10)
                pt.add_column("URL", style="dim")
                for p in data["identity_proofs"]:
                    pt.add_row(
                        p["service"],
                        p["username"],
                        "[green]✔[/green]" if p["state"] == 1 else "[yellow]?[/yellow]",
                        p["url"][:50]
                    )
                console.print(pt)

            if platform in ("npm", "PyPI") and data.get("packages"):
                pkt = Table(title=f"{platform} Packages", show_header=True, header_style="bold blue")
                pkt.add_column("Package", style="cyan", width=25)
                pkt.add_column("Description", style="dim")
                for p in data["packages"]:
                    pkt.add_row(p["name"], p.get("description", "")[:60])
                console.print(pkt)

        correlation = self.correlate()

        corr_lines = [
            f"[bold]Platforms found:[/bold] {correlation['total_found']} / {len(scanners)} "
            f"({', '.join(correlation['platforms_found']) or 'none'})",
        ]
        if correlation["names"]:
            corr_lines.append(f"[bold]Real names:[/bold] {', '.join(correlation['names'])}")
        if correlation["emails"]:
            corr_lines.append(f"[bold]Emails:[/bold] {', '.join(correlation['emails'])}")
        if correlation["locations"]:
            corr_lines.append(f"[bold]Locations:[/bold] {', '.join(correlation['locations'])}")

        console.print(Panel("\n".join(corr_lines), title="Cross-Platform Correlation", border_style="blue"))

        if correlation["linked_accounts"]:
            lt = Table(title="Linked Accounts", show_header=True, header_style="bold magenta")
            lt.add_column("Platform", style="cyan", width=15)
            lt.add_column("Username", style="yellow", width=20)
            lt.add_column("Found via", style="dim", width=12)
            lt.add_column("Verified", justify="center", width=10)
            for la in correlation["linked_accounts"]:
                lt.add_row(
                    la["platform"],
                    la["username"],
                    la.get("found_via", ""),
                    "[green]✔[/green]" if la.get("verified") else "—"
                )
            console.print(lt)

        if self.sources_skipped:
            console.print("\n[yellow]Skipped sources (add API keys to .env to enable):[/yellow]")
            for s in self.sources_skipped:
                console.print(f"  [dim]• {s}[/dim]")

        Config.ensure_dirs()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = f"logs/username_osint_{self.username}_{ts}.json"
        with open(fn, "w") as f:
            json.dump({
                "username": self.username,
                "scan_time": datetime.now().isoformat(),
                "profiles": self.profiles,
                "correlation": correlation,
                "sources_skipped": self.sources_skipped,
            }, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"\n[green]✔ Saved: {fn}[/green]")

        console.print(Panel(
            f"[bold]Found on:[/bold] {correlation['total_found']} platform(s)  |  "
            f"[bold]Skipped:[/bold] {len(self.sources_skipped)}  |  "
            f"[bold]Linked accounts:[/bold] {len(correlation['linked_accounts'])}",
            title="Summary",
            border_style="blue"
        ))


def main():
    console.print(Panel(
        "[bold cyan]USERNAME OSINT — OSINT-Hunter V3[/bold cyan]\n"
        "[dim]GitHub • Reddit • Twitter/X • Mastodon • Keybase • HackerNews • Dev.to • npm • PyPI[/dim]\n"
        "[dim]Official APIs only — exact match — no false positives[/dim]",
        border_style="cyan"
    ))
    u = input("\n  Enter username (without @): ").strip()
    if not u:
        console.print("[red]❌ Empty![/red]")
        return
    UsernameOSINT(u).run()


if __name__ == "__main__":
    main()
