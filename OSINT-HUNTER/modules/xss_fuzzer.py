import requests
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
from datetime import datetime
import os

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0"}

def fetch_payloads(proxy=None):
    console.print("[cyan]→ Mengambil payload XSS dari GitHub...[/cyan]")
    url = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/README.md"
    payloads = []
    try:
        res = requests.get(url, headers=HEADERS, timeout=10, proxies=proxy)
        matches = re.findall(r'`(.*?)`', res.text)
        for p in matches:
            if "<script>" in p or "alert" in p or "onerror" in p:
                payloads.append(p)
        payloads = list(set(payloads))
        console.print(f"[green]✔ Found {len(payloads)} payload XSS.[/green]")
    except Exception as e:
        console.print(f"[red]Failed to fetch payloads: {e}[/red]")
    return payloads[:30]

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def fuzz_xss(url, param_list, payloads, proxy=None):
    console.print(f"[cyan]→ Fuzzing XSS on {url}[/cyan]")
    result = {
        "target": url,
        "tested_params": [],
        "xss_found": []
    }
    for param in param_list:
        for payload in payloads:
            test_url = inject_payload(url, param, payload)
            try:
                res = requests.get(test_url, headers=HEADERS, timeout=5, proxies=proxy)
                if payload in res.text:
                    console.print(f"[bold green][+]Reflected XSS found in param: {param}[/bold green]")
                    result["xss_found"].append({
                        "url": test_url,
                        "param": param,
                        "payload": payload
                    })
                    break
            except:
                continue
        result["tested_params"].append(param)
    return result

def save_json(data, domain):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/xss_fuzz_{domain}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    console.print(f"[green]✔ XSS Result saved to {filename}[/green]")

def run(proxy=None):
    try:
        console.print("\n[bold cyan]:: XSS PARAM FUZZER MODULE[/bold cyan]")
        target = input("Enter the target URL (with ?param=): ").strip()
        parsed = urlparse(target)
        domain = parsed.netloc

        if not parsed.query:
            console.print("[red]URL must contain parameters! Example: ?q=abc[/red]")
            return

        param_list = list(parse_qs(parsed.query).keys())
        if not param_list:
            console.print("[red]Failed to parse parameters[/red]")
            return

        payloads = fetch_payloads(proxy)
        results = fuzz_xss(target, param_list, payloads, proxy)
        save_json(results, domain)
        console.print("[bold green]✓ XSS fuzzing complete[/bold green]")

    except KeyboardInterrupt:
        console.print("\n[red]❌ Canceled by user (Ctrl+C)[/red]")
