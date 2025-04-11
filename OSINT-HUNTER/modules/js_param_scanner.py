import re
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from rich.console import Console
from datetime import datetime
import os

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0"}

def extract_from_content(content):
    endpoints = re.findall(r"[\"'](\/[a-zA-Z0-9_\-\/\.?=]+)[\"']", content)
    secrets = re.findall(r"[\"']([a-zA-Z0-9_\-]{16,})[\"']", content)
    urls = re.findall(r"https?:\/\/[a-zA-Z0-9_\-\.\/\?\&\=]+", content)

    secrets_found = []
    for sec in secrets:
        if any(key in sec.lower() for key in ['key', 'token', 'auth', 'bearer']):
            secrets_found.append(sec)

    return {
        "endpoints": list(set(endpoints)),
        "external_urls": list(set(urls)),
        "sensitive_tokens": list(set(secrets_found))
    }

def get_js_links(url, proxy=None, result_dict=None):
    console.print(f"[cyan]→ Search for .js files and inline scripts on the main page: {url}[/cyan]")
    js_files = []
    try:
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, "html.parser")
        scripts = soup.find_all("script")

        for s in scripts:
            src = s.get("src")
            if src:
                full_url = urljoin(url, src)
                if full_url not in js_files:
                    js_files.append(full_url)
            else:
                inline = s.string or s.get_text()
                if inline and len(inline.strip()) > 20:
                    inline_id = f"{urlparse(url).netloc}_inline_{abs(hash(inline))}"
                    extracted = extract_from_content(inline)
                    if extracted and result_dict is not None:
                        result_dict["scanned_files"][inline_id] = extracted

    except Exception as e:
        console.print(f"[red]Error parsing HTML: {e}[/red]")
    return js_files

def extract_endpoints(js_url, proxy=None):
    console.print(f"[yellow]→ Scanning {js_url}[/yellow]")
    try:
        res = requests.get(js_url, headers=HEADERS, timeout=10, proxies=proxy)
        return extract_from_content(res.text)
    except Exception as e:
        console.print(f"[red]Scan failed {js_url}: {e}[/red]")
        return {}

def get_wayback_urls(domain, proxy=None):
    console.print(f"[cyan]→ Retrieving URL from Wayback Machine[/cyan]")
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        raw = res.json()
        return [entry[0] for entry in raw[1:] if entry[0].endswith(".js")]
    except:
        return []

def extract_params_from_endpoints(endpoints):
    params = []
    for ep in endpoints:
        if '?' in ep:
            parts = ep.split('?')[1]
            for p in parts.split('&'):
                key = p.split('=')[0]
                if key and key not in params:
                    params.append(key)
    return params

def save_json(data, target):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/js_scan_{target}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    console.print(f"[green]✔ Saved to {filename}[/green]")

def run(proxy=None):
    try:
        console.print("\n[bold cyan]:: JS PARAMETER SCANNER MODULE[/bold cyan]")
        target = input("Enter a URL (example: http://target.com): ").strip()
        if not target.startswith("http"):
            console.print("[red]UURL must start with http:// or https://[/red]")
            return

        domain = urlparse(target).netloc
        result = {
            "target": target,
            "js_files": [],
            "scanned_files": {},
            "wayback_js": [],
            "all_params": []
        }

        js_links = get_js_links(target, proxy, result_dict=result)
        result["js_files"] = js_links

        wayback_js = get_wayback_urls(domain, proxy)
        result["wayback_js"] = wayback_js

        all_js = list(set(js_links + wayback_js))

        all_endpoints = []
        for js in all_js:
            found = extract_endpoints(js, proxy)
            if found:
                result["scanned_files"][js] = found
                all_endpoints.extend(found.get("endpoints", []))

        all_params = extract_params_from_endpoints(all_endpoints)
        result["all_params"] = all_params

        save_json(result, domain)
        console.print("[bold green]✓ JS scan complete![/bold green]")

    except KeyboardInterrupt:
        console.print("\n[red]❌ Canceled by user (Ctrl+C)[/red]")
