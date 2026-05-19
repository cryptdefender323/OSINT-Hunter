#!/usr/bin/env python3

import re
import os
import json
import time
import sys
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()

PLATFORMS = {
    "GitHub": {
        "url": "https://github.com/{}",
        "not_found_strings": ["Not Found", "This is not the web page you are looking for"],
        "profile_indicators": ["repositories", "followers", "following"],
        "title_pattern": r"^{username}\s*\(",
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/about.json",
        "api": True,
        "not_found_strings": [],
        "profile_indicators": ["link_karma", "comment_karma", "created_utc"],
    },
    "GitLab": {
        "url": "https://gitlab.com/{}",
        "not_found_strings": ["404", "Page Not Found"],
        "profile_indicators": ["projects", "groups", "followers"],
    },
    "HackerNews": {
        "url": "https://hacker-news.firebaseio.com/v0/user/{}.json",
        "api": True,
        "not_found_strings": [],
        "profile_indicators": ["karma", "created", "submitted"],
    },
    "Keybase": {
        "url": "https://keybase.io/{}",
        "not_found_strings": ["Sorry, that user doesn't exist", "Not found"],
        "profile_indicators": ["proofs", "followers", "following"],
    },
    "Dev.to": {
        "url": "https://dev.to/{}",
        "not_found_strings": ["404", "page not found"],
        "profile_indicators": ["articles", "comments", "joined"],
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "not_found_strings": ["Page not found", "This page doesn't exist"],
        "profile_indicators": ["followers", "following", "stories"],
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "not_found_strings": ["The specified profile could not be found", "error_ctn"],
        "profile_indicators": ["games", "friends", "level"],
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{}",
        "not_found_strings": ["Sorry. Unless you've got a time machine"],
        "profile_indicators": ["followers", "following", "stream"],
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{}",
        "not_found_strings": ["We can't find that user", "404"],
        "profile_indicators": ["followers", "following", "tracks"],
    },
    "HackerRank": {
        "url": "https://www.hackerrank.com/{}",
        "not_found_strings": ["404"],
        "profile_indicators": ["rank", "score", "badges"],
    },
    "LeetCode": {
        "url": "https://leetcode.com/{}",
        "not_found_strings": ["404", "Page Not Found"],
        "profile_indicators": ["solved", "submissions", "ranking"],
    },
    "CodeWars": {
        "url": "https://www.codewars.com/users/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["honor", "rank", "kata"],
    },
    "Replit": {
        "url": "https://replit.com/@{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["repls", "followers", "following"],
    },
    "Docker Hub": {
        "url": "https://hub.docker.com/u/{}",
        "not_found_strings": ["Page Not Found", "404"],
        "profile_indicators": ["repositories", "stars"],
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{}",
        "not_found_strings": ["Not found", "404"],
        "profile_indicators": ["packages", "downloads"],
    },
    "PyPI": {
        "url": "https://pypi.org/user/{}/",
        "not_found_strings": ["404", "Not Found"],
        "profile_indicators": ["projects", "packages"],
    },
    "Dribbble": {
        "url": "https://dribbble.com/{}",
        "not_found_strings": ["Whoops", "404"],
        "profile_indicators": ["shots", "followers", "following"],
    },
    "Behance": {
        "url": "https://www.behance.net/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["projects", "followers", "appreciations"],
    },
    "Vimeo": {
        "url": "https://vimeo.com/{}",
        "not_found_strings": ["Sorry, we couldn't find that page", "404"],
        "profile_indicators": ["videos", "followers", "following"],
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{}",
        "not_found_strings": ["Gravatar Profile Not Found", "hasn't claimed"],
        "profile_indicators": ["profile", "accounts"],
    },
    "Lichess": {
        "url": "https://lichess.org/@/{}",
        "not_found_strings": ["No such user", "404"],
        "profile_indicators": ["games", "rating", "followers"],
    },
    "Chess.com": {
        "url": "https://www.chess.com/member/{}",
        "not_found_strings": ["Oops! That page can", "404"],
        "profile_indicators": ["games", "rating", "followers"],
    },
    "Wattpad": {
        "url": "https://www.wattpad.com/user/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["stories", "followers", "following"],
    },
    "Imgur": {
        "url": "https://imgur.com/user/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["posts", "comments", "followers"],
    },
    "Fiverr": {
        "url": "https://www.fiverr.com/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["gigs", "reviews", "rating"],
    },
    "Ko-fi": {
        "url": "https://ko-fi.com/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["supporters", "posts"],
    },
    "Patreon": {
        "url": "https://www.patreon.com/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["patrons", "posts"],
    },
    "Tumblr": {
        "url": "https://{}.tumblr.com",
        "not_found_strings": ["There's nothing here", "404"],
        "profile_indicators": ["posts", "followers"],
    },
    "VK": {
        "url": "https://vk.com/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["friends", "followers", "posts"],
    },
    "About.me": {
        "url": "https://about.me/{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["about", "profile"],
    },
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{}",
        "not_found_strings": ["404", "not found"],
        "profile_indicators": ["upvotes", "products", "followers"],
    },
    "Pastebin": {
        "url": "https://pastebin.com/u/{}",
        "not_found_strings": ["Not Found"],
        "profile_indicators": ["pastes", "public pastes"],
    },
}

STATUS_VERIFIED = "VERIFIED_MATCH"
STATUS_HIGH = "HIGH_CONFIDENCE"
STATUS_MEDIUM = "MEDIUM_CONFIDENCE"
STATUS_LOW = "LOW_CONFIDENCE"
STATUS_FP = "POSSIBLE_FALSE_POSITIVE"
STATUS_NOT_FOUND = "NOT_FOUND"

LOGIN_WALL_URL_PATTERNS = [
    "/login", "/signin", "/auth", "/account/login",
]
LOGIN_WALL_DOMAINS = ["accounts.", "login.", "auth."]
LOGIN_WALL_BODY = [
    "sign in to continue", "log in to see", "create an account",
    "login to view", "please log in",
]
GENERIC_NOT_FOUND_BODY = [
    "page not found", "doesn't exist", "no such user", "user not found",
    "this account has been suspended", "this account doesn't exist",
    "create your account", "join now to",
]
ACTIVE_PROFILE_PATTERNS = [
    r"\d+\s*(?:followers|following|subscribers)",
    r"\d+\s*(?:posts|tweets|videos|articles|shots|tracks|repls|gigs)",
    r"joined\s+\w+\s+\d{4}",
    r"member since",
    r"last seen",
    r"last active",
    r"\bonline\b",
]


def _score_result(username, res_text, final_url, status_code, platform_data, soup):
    score = 0
    signals = []

    body_lower = res_text.lower()
    uname_lower = username.lower()

    title_tag = soup.find("title")
    title_text = title_tag.get_text() if title_tag else ""
    og_title_tag = soup.find("meta", property="og:title")
    og_title = og_title_tag.get("content", "") if og_title_tag else ""
    og_desc_tag = soup.find("meta", property="og:description")
    og_desc = og_desc_tag.get("content", "") if og_desc_tag else ""
    meta_desc_tag = soup.find("meta", attrs={"name": "description"})
    meta_desc = meta_desc_tag.get("content", "") if meta_desc_tag else ""
    og_img_tag = soup.find("meta", property="og:image")
    og_img = og_img_tag.get("content", "") if og_img_tag else ""
    canonical_tag = soup.find("link", rel="canonical")
    canonical = canonical_tag.get("href", "") if canonical_tag else ""

    title_pattern = platform_data.get("title_pattern", "")
    if title_pattern:
        pattern = title_pattern.replace("{username}", re.escape(username))
        if re.search(pattern, title_text, re.IGNORECASE):
            score += 25
            signals.append("username_exact_title")
    elif uname_lower in title_text.lower():
        score += 25
        signals.append("username_in_title")

    if uname_lower in og_title.lower():
        score += 20
        signals.append("username_in_og_title")

    if uname_lower in og_desc.lower() or uname_lower in meta_desc.lower():
        score += 15
        signals.append("username_in_description")

    if og_img and not _is_generic_image(og_img):
        score += 10
        signals.append("profile_avatar_found")

    if canonical and f"/{username}" in canonical:
        score += 10
        signals.append("username_in_canonical_path")
        score += 5
        signals.append("username_in_canonical_url")
    elif canonical and uname_lower in canonical.lower():
        score += 5
        signals.append("username_in_canonical_url")

    for indicator in platform_data.get("profile_indicators", []):
        if indicator.lower() in body_lower:
            score += 10
            signals.append(f"profile_indicator:{indicator}")
            break

    for pat in ACTIVE_PROFILE_PATTERNS:
        if re.search(pat, body_lower):
            score += 10
            signals.append("active_profile_pattern")
            break

    parsed_final = urlparse(final_url)
    final_path = parsed_final.path.lower()
    final_domain = parsed_final.netloc.lower()

    for lw_path in LOGIN_WALL_URL_PATTERNS:
        if lw_path in final_path:
            score -= 30
            signals.append("login_wall_url")
            break

    for lw_domain in LOGIN_WALL_DOMAINS:
        if final_domain.startswith(lw_domain):
            score -= 30
            signals.append("login_wall_domain")
            break

    for lw_body in LOGIN_WALL_BODY:
        if lw_body in body_lower:
            score -= 30
            signals.append("login_wall_body")
            break

    for nf_str in GENERIC_NOT_FOUND_BODY:
        if nf_str in body_lower:
            score -= 20
            signals.append("generic_not_found_body")
            break

    for nf_str in platform_data.get("not_found_strings", []):
        if nf_str.lower() in body_lower:
            score -= 20
            signals.append("platform_not_found_string")
            break

    original_url = platform_data["url"].split("{}")[0]
    original_domain = urlparse("https://" + original_url.split("//")[-1]).netloc
    if parsed_final.netloc and parsed_final.netloc == original_domain:
        path_stripped = parsed_final.path.strip("/")
        if not path_stripped or path_stripped in ("", "home", "index"):
            score -= 15
            signals.append("redirect_to_homepage")

    if "captcha" in body_lower or "robot" in body_lower or "are you human" in body_lower:
        score -= 10
        signals.append("captcha_detected")

    return score, signals


def _is_generic_image(url):
    generic_patterns = [
        "default", "placeholder", "generic", "blank", "avatar_default",
        "no-image", "noimage", "logo", "icon", "favicon",
    ]
    url_lower = url.lower()
    return any(p in url_lower for p in generic_patterns)


def _status_from_score(score, status_code):
    if status_code == 404 or score <= 0:
        return STATUS_NOT_FOUND
    if score >= 75:
        return STATUS_VERIFIED
    if score >= 55:
        return STATUS_HIGH
    if score >= 35:
        return STATUS_MEDIUM
    if score >= 15:
        return STATUS_LOW
    return STATUS_FP


def _extract_profile_meta(soup, username):
    meta = {}

    og_title_tag = soup.find("meta", property="og:title")
    if og_title_tag:
        meta["display_name"] = og_title_tag.get("content", "").strip()

    og_desc_tag = soup.find("meta", property="og:description")
    if og_desc_tag:
        meta["bio"] = og_desc_tag.get("content", "")[:300].strip()

    og_img_tag = soup.find("meta", property="og:image")
    if og_img_tag:
        img = og_img_tag.get("content", "")
        if img and not _is_generic_image(img):
            meta["avatar_url"] = img

    title_tag = soup.find("title")
    if title_tag and "display_name" not in meta:
        meta["display_name"] = title_tag.get_text().strip()

    linked = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.startswith("http") and username.lower() not in href.lower():
            parsed = urlparse(href)
            if parsed.netloc and parsed.netloc not in ("", "javascript:"):
                linked.append(href)
    if linked:
        meta["linked_urls"] = list(dict.fromkeys(linked))[:10]

    return meta


def _check_api_platform(platform, username, platform_data, url):
    result = {
        "platform": platform,
        "url": url,
        "status": STATUS_NOT_FOUND,
        "score": 0,
        "signals": [],
        "profile_meta": {},
        "response_time_ms": 0,
        "status_code": None,
        "is_permutation": False,
    }

    try:
        headers = {"User-Agent": "OSINT-Hunter-V3"}
        session = requests.Session()
        proxy = Config.get_proxy_dict()
        if proxy:
            session.proxies = proxy

        t0 = time.time()
        res = session.get(url, headers=headers, timeout=10, allow_redirects=True)
        result["response_time_ms"] = int((time.time() - t0) * 1000)
        result["status_code"] = res.status_code

        if res.status_code == 404:
            return result

        body = res.text.strip()
        if body in ("null", "", "[]", "{}"):
            return result

        try:
            data = res.json()
        except Exception:
            return result

        if isinstance(data, dict) and data.get("error") == 404:
            return result

        if not isinstance(data, dict) or not data:
            return result

        indicators = platform_data.get("profile_indicators", [])
        matched = [k for k in indicators if k in data]
        if not matched:
            return result

        score = 60 + len(matched) * 5
        signals = [f"api_field:{k}" for k in matched]

        result["score"] = min(score, 100)
        result["status"] = _status_from_score(result["score"], res.status_code)
        result["signals"] = signals

        meta = {}
        for field in ("name", "display_name", "username", "login"):
            if field in data and data[field]:
                meta["display_name"] = str(data[field])
                break
        for field in ("about", "bio", "description"):
            if field in data and data[field]:
                meta["bio"] = str(data[field])[:300]
                break
        if meta:
            result["profile_meta"] = meta

    except requests.exceptions.Timeout:
        result["status"] = "timeout"
    except Exception:
        pass

    return result


def check_platform(platform, username, platform_data, is_permutation=False):
    url = platform_data["url"].format(username)
    result = {
        "platform": platform,
        "url": url,
        "status": STATUS_NOT_FOUND,
        "score": 0,
        "signals": [],
        "profile_meta": {},
        "response_time_ms": 0,
        "status_code": None,
        "is_permutation": is_permutation,
    }

    if platform_data.get("api"):
        r = _check_api_platform(platform, username, platform_data, url)
        r["is_permutation"] = is_permutation
        return r

    try:
        headers = {"User-Agent": Config.get_random_ua()}
        session = requests.Session()
        proxy = Config.get_proxy_dict()
        if proxy:
            session.proxies = proxy

        t0 = time.time()
        res = session.get(url, headers=headers, timeout=12, allow_redirects=True)
        result["response_time_ms"] = int((time.time() - t0) * 1000)
        result["status_code"] = res.status_code

        if res.status_code == 404:
            return result

        if res.status_code not in (200, 301, 302):
            return result

        soup = BeautifulSoup(res.text, "html.parser")
        score, signals = _score_result(
            username, res.text, res.url, res.status_code, platform_data, soup
        )

        result["score"] = score
        result["signals"] = signals
        result["status"] = _status_from_score(score, res.status_code)
        result["profile_meta"] = _extract_profile_meta(soup, username)
        result["final_url"] = res.url

    except requests.exceptions.Timeout:
        result["status"] = "timeout"
    except requests.exceptions.ConnectionError:
        result["status"] = "error"
    except Exception:
        result["status"] = "error"

    return result


def generate_permutations(username):
    variants = [
        (f"_{username}", True),
        (f"{username}_", True),
        (f"{username}1", True),
        (f"{username}123", True),
        (f"{username}_official", True),
        (f"{username}_real", True),
        (f"the{username}", True),
    ]
    return variants


def correlate_results(results):
    found = [r for r in results if r["status"] in (STATUS_VERIFIED, STATUS_HIGH, STATUS_MEDIUM)]
    if not found:
        return {}

    display_names = {}
    avatar_domains = {}
    bio_keywords = {}
    linked_urls = {}

    for r in found:
        meta = r.get("profile_meta", {})
        plat = r["platform"]

        dn = meta.get("display_name", "")
        if dn:
            dn_clean = dn.strip()
            display_names.setdefault(dn_clean, [])
            if plat not in display_names[dn_clean]:
                display_names[dn_clean].append(plat)

        av = meta.get("avatar_url", "")
        if av:
            domain = urlparse(av).netloc
            if domain:
                avatar_domains.setdefault(domain, [])
                if plat not in avatar_domains[domain]:
                    avatar_domains[domain].append(plat)

        bio = meta.get("bio", "")
        if bio:
            words = re.findall(r"\b[a-z]{4,}\b", bio.lower())
            for w in set(words):
                bio_keywords.setdefault(w, [])
                if plat not in bio_keywords[w]:
                    bio_keywords[w].append(plat)

        for link in meta.get("linked_urls", []):
            linked_urls.setdefault(link, [])
            if plat not in linked_urls[link]:
                linked_urls[link].append(plat)

    correlation = {}

    multi_dn = {k: v for k, v in display_names.items() if len(v) >= 2}
    if multi_dn:
        correlation["display_names"] = multi_dn

    multi_av = {k: v for k, v in avatar_domains.items() if len(v) >= 2}
    if multi_av:
        correlation["avatar_domains"] = multi_av

    common_kw = {k: v for k, v in bio_keywords.items() if len(v) >= 3}
    if common_kw:
        top_kw = sorted(common_kw.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        correlation["bio_keywords"] = dict(top_kw)

    multi_links = {k: v for k, v in linked_urls.items() if len(v) >= 2}
    if multi_links:
        correlation["linked_urls"] = multi_links

    return correlation


def generate_html_report(username, results, folder):
    verified = [r for r in results if r["status"] == STATUS_VERIFIED]
    high = [r for r in results if r["status"] == STATUS_HIGH]
    medium = [r for r in results if r["status"] == STATUS_MEDIUM]
    found_count = len(verified) + len(high) + len(medium)

    status_color = {
        STATUS_VERIFIED: "#3fb950",
        STATUS_HIGH: "#58a6ff",
        STATUS_MEDIUM: "#d29922",
        STATUS_LOW: "#8b949e",
        STATUS_FP: "#6e7681",
        STATUS_NOT_FOUND: "#f85149",
    }

    def rows_html(result_list):
        html = ""
        for r in sorted(result_list, key=lambda x: x["score"], reverse=True):
            meta = r.get("profile_meta", {})
            dn = meta.get("display_name", "")[:40]
            bio = meta.get("bio", "")[:80]
            color = status_color.get(r["status"], "#8b949e")
            perm = " [perm]" if r.get("is_permutation") else ""
            html += f"""
        <tr>
            <td>{r['platform']}{perm}</td>
            <td style="color:{color};font-weight:bold">{r['status']}</td>
            <td style="color:{color}">{r['score']}</td>
            <td><a href="{r['url']}" target="_blank">{r['url'][:60]}</a></td>
            <td>{dn}</td>
            <td style="color:#8b949e;font-size:12px">{bio}</td>
            <td>{r['response_time_ms']}ms</td>
        </tr>"""
        return html

    all_display = verified + high + medium
    body_rows = rows_html(all_display)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Username Intelligence Report — {username}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }}
        h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
        h2 {{ color: #8b949e; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-top: 32px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
        th {{ background: #161b22; color: #58a6ff; padding: 10px 12px; text-align: left; }}
        td {{ padding: 9px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
        tr:hover {{ background: #161b22; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .stats {{ display: flex; gap: 16px; margin: 20px 0; flex-wrap: wrap; }}
        .stat-card {{ background: #161b22; padding: 18px 24px; border-radius: 8px; min-width: 120px; text-align: center; border: 1px solid #30363d; }}
        .stat-num {{ font-size: 32px; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ font-size: 12px; color: #8b949e; margin-top: 4px; }}
        .footer {{ margin-top: 40px; color: #484f58; font-size: 12px; text-align: center; }}
        .signals {{ font-size: 11px; color: #6e7681; }}
    </style>
</head>
<body>
    <h1>Username Intelligence Report: {username}</h1>
    <p style="color:#8b949e">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <div class="stats">
        <div class="stat-card"><div class="stat-num">{len(results)}</div><div class="stat-label">Platforms Checked</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#3fb950">{len(verified)}</div><div class="stat-label">Verified Match</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#58a6ff">{len(high)}</div><div class="stat-label">High Confidence</div></div>
        <div class="stat-card"><div class="stat-num" style="color:#d29922">{len(medium)}</div><div class="stat-label">Medium Confidence</div></div>
    </div>
    <h2>Confirmed Accounts ({found_count})</h2>
    <table>
        <tr><th>Platform</th><th>Status</th><th>Score</th><th>URL</th><th>Display Name</th><th>Bio</th><th>Time</th></tr>
        {body_rows}
    </table>
    <div class="footer">OSINT-Hunter V3 &bull; {datetime.now().year}</div>
</body>
</html>"""

    path = f"{folder}/report_{username}.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def _render_correlation_panel(correlation):
    if not correlation:
        return

    lines = []
    for dn, platforms in correlation.get("display_names", {}).items():
        lines.append(f'  [bold]Display name:[/bold] "{dn}" ([cyan]{", ".join(platforms)}[/cyan])')
    for domain, platforms in correlation.get("avatar_domains", {}).items():
        lines.append(f'  [bold]Avatar domain:[/bold] {domain} ([cyan]{", ".join(platforms)}[/cyan])')
    for kw, platforms in correlation.get("bio_keywords", {}).items():
        lines.append(f'  [bold]Bio keyword:[/bold] "{kw}" ([cyan]{", ".join(platforms)}[/cyan])')
    for link, platforms in correlation.get("linked_urls", {}).items():
        short = link[:60]
        lines.append(f'  [bold]Linked URL:[/bold] {short} ([cyan]{", ".join(platforms)}[/cyan])')

    if lines:
        console.print(Panel(
            "\n".join(lines),
            title="[bold yellow]Cross-Platform Signals[/bold yellow]",
            border_style="yellow",
        ))


def _render_main_table(username, verified, high):
    if not verified and not high:
        return

    table = Table(
        title=f"[bold green]Confirmed Accounts — {username}[/bold green]",
        show_header=True,
        header_style="bold green",
        border_style="green",
    )
    table.add_column("Status", width=18)
    table.add_column("Platform", style="cyan", width=16)
    table.add_column("Score", justify="right", width=6)
    table.add_column("URL", style="yellow")

    for r in sorted(verified, key=lambda x: x["score"], reverse=True):
        perm = " [dim](perm)[/dim]" if r.get("is_permutation") else ""
        table.add_row(
            f"[bold green]{STATUS_VERIFIED}[/bold green]",
            r["platform"] + perm,
            f"[green]{r['score']}[/green]",
            r["url"],
        )
    for r in sorted(high, key=lambda x: x["score"], reverse=True):
        perm = " [dim](perm)[/dim]" if r.get("is_permutation") else ""
        table.add_row(
            f"[bold blue]{STATUS_HIGH}[/bold blue]",
            r["platform"] + perm,
            f"[blue]{r['score']}[/blue]",
            r["url"],
        )

    console.print(table)


def _render_medium_section(medium):
    if not medium:
        return

    table = Table(
        title="[dim]Possible Matches (Medium Confidence)[/dim]",
        show_header=True,
        header_style="dim",
        border_style="bright_black",
    )
    table.add_column("Platform", style="dim cyan", width=16)
    table.add_column("Score", justify="right", width=6)
    table.add_column("URL", style="dim")

    for r in sorted(medium, key=lambda x: x["score"], reverse=True):
        perm = " (perm)" if r.get("is_permutation") else ""
        table.add_row(
            r["platform"] + perm,
            str(r["score"]),
            r["url"],
        )

    console.print(table)


def main():
    console.print(Panel(
        "[bold cyan]Advanced Username Intelligence Engine[/bold cyan]\n"
        "[dim]Confidence-scored account detection across 35+ platforms[/dim]",
        border_style="cyan",
    ))

    username = input("\n  Enter username: ").strip()
    if not username:
        console.print("[red]No username provided.[/red]")
        return

    do_perms = input("  Check username permutations? (y/N): ").strip().lower() == "y"

    folder = f"results/{username}"
    os.makedirs(folder, exist_ok=True)

    tasks = [(name, username, data, False) for name, data in PLATFORMS.items()]

    if do_perms:
        perm_variants = generate_permutations(username)
        for variant, _ in perm_variants:
            for name, data in PLATFORMS.items():
                tasks.append((name, variant, data, True))

    total = len(tasks)
    console.print(f"\n[bold blue]Scanning {total} checks for '{username}'...[/bold blue]\n")

    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Scanning platforms...", total=total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(check_platform, plat, uname, pdata, is_perm): (plat, uname)
                for plat, uname, pdata, is_perm in tasks
            }
            for future in concurrent.futures.as_completed(futures):
                r = future.result()
                results.append(r)
                if r["status"] in (STATUS_VERIFIED, STATUS_HIGH):
                    label = "[green]VERIFIED[/green]" if r["status"] == STATUS_VERIFIED else "[blue]HIGH[/blue]"
                    perm_note = " [dim](perm)[/dim]" if r.get("is_permutation") else ""
                    console.print(
                        f"  {label}  [cyan]{r['platform']}[/cyan]{perm_note}  "
                        f"[dim]{r['score']}[/dim]  {r['url']}"
                    )
                progress.update(task_id, advance=1)

    verified = [r for r in results if r["status"] == STATUS_VERIFIED]
    high = [r for r in results if r["status"] == STATUS_HIGH]
    medium = [r for r in results if r["status"] == STATUS_MEDIUM]

    console.print()
    _render_main_table(username, verified, high)
    _render_medium_section(medium)

    correlation = correlate_results(results)
    _render_correlation_panel(correlation)

    found_count = len(verified) + len(high) + len(medium)
    console.print(Panel(
        f"[green]Verified:[/green] {len(verified)}  "
        f"[blue]High:[/blue] {len(high)}  "
        f"[yellow]Medium:[/yellow] {len(medium)}  "
        f"[dim]Platforms checked:[/dim] {len(PLATFORMS)}",
        title="Scan Summary",
        border_style="blue",
    ))

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"{folder}/lookup_{username}_{timestamp}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "target": username,
                "scan_time": datetime.now().isoformat(),
                "permutations_checked": do_perms,
                "platforms_checked": len(PLATFORMS),
                "total_checks": total,
                "summary": {
                    "verified": len(verified),
                    "high_confidence": len(high),
                    "medium_confidence": len(medium),
                    "found_total": found_count,
                },
                "correlation": correlation,
                "results": results,
            },
            f,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
    console.print(f"[green]✓ JSON:[/green] {json_path}")

    html_path = generate_html_report(username, results, folder)
    console.print(f"[green]✓ HTML:[/green] {html_path}")


if __name__ == "__main__":
    main()
