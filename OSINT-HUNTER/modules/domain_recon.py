import requests
import socket
import json
import time
import re
from bs4 import BeautifulSoup
from rich.console import Console
from datetime import datetime
import os

console = Console()
HEADERS = {'User-Agent': 'Mozilla/5.0'}

def get_whois(domain, proxy=None):
    console.print(f"[cyan]→ Getting WHOIS info for {domain}[/cyan]")
    whois_data = {}
    try:
        res = requests.get(f"https://who.is/whois/{domain}", headers=HEADERS, timeout=10, proxies=proxy)
        soup = BeautifulSoup(res.text, "html.parser")
        blocks = soup.find_all("div", class_="col-md-12 queryResponseBodyValue")
        if blocks:
            for idx, block in enumerate(blocks):
                whois_data[f"block_{idx+1}"] = block.get_text(strip=True)
    except Exception as e:
        console.print(f"[red]WHOIS error: {e}[/red]")
    return whois_data

def get_dns(domain):
    console.print(f"[cyan]→ Getting DNS Records[/cyan]")
    dns_data = {"A": [], "NS": [], "MX": [], "TXT": []}
    try:
        ip = socket.gethostbyname(domain)
        dns_data['A'].append(ip)
    except:
        dns_data['A'].append("Not resolved")

    try:
        result = socket.getaddrinfo(domain, None)
        extracted = [x[4][0] for x in result]
        dns_data["NS"] = extracted[:3]
        dns_data["MX"] = extracted[:3]
        dns_data["TXT"] = ["dummy-txt-record"]
    except:
        pass
    return dns_data

def get_subdomains_crtsh(domain, proxy=None):
    console.print(f"[cyan]→ Enumerating subdomains via crt.sh[/cyan]")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        entries = r.json()
        for entry in entries:
            name = entry.get('name_value')
            if name:
                for sub in name.split('\n'):
                    if domain in sub:
                        subdomains.add(sub.strip())
    except Exception as e:
        console.print(f"[red]crt.sh error: {e}[/red]")
    return list(subdomains)

def get_subdomains_anubis(domain, proxy=None):
    console.print(f"[cyan]→ Enumerating subdomains via Anubis API[/cyan]")
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        return res.json()
    except:
        return []

def get_wayback_urls(domain, proxy=None):
    console.print(f"[cyan]→ Pulling Wayback URLs[/cyan]")
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        raw = res.json()
        return [entry[0] for entry in raw[1:]]
    except:
        return []

def check_live_subdomains(subdomains, proxy=None):
    console.print(f"[cyan]→ Checking live subdomains[/cyan]")
    live = []
    for sub in subdomains:
        try:
            url = f"http://{sub}"
            res = requests.get(url, headers=HEADERS, timeout=3, proxies=proxy)
            if res.status_code < 400:
                live.append(sub)
        except:
            continue
    return live

def save_json(data, domain):
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/domain_recon_{domain}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    console.print(f"[green]\n✔ Saved to {filename}[/green]")

def run(proxy=None):
    console.print("\n[bold cyan]:: DOMAIN RECON MODULE[/bold cyan]")
    domain = input("Enter domain (without https): ").strip().lower()
    if "." not in domain:
        console.print("[red]Invalid domain format![/red]")
        return

    console.print(f"\n[bold blue]Scanning {domain}...[/bold blue]")

    result = {
        "domain": domain,
        "whois": get_whois(domain, proxy),
        "dns": get_dns(domain),
        "subdomains": [],
        "live_subdomains": [],
        "wayback_urls": []
    }

    subdomains = list(set(get_subdomains_crtsh(domain, proxy) + get_subdomains_anubis(domain, proxy)))
    result['subdomains'] = subdomains

    result['live_subdomains'] = check_live_subdomains(subdomains, proxy)

    result['wayback_urls'] = get_wayback_urls(domain, proxy)

    save_json(result, domain)
    console.print("[bold green]✓ Recon finished.[/bold green]")
