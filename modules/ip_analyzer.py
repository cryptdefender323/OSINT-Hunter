#!/usr/bin/env python3

import os
import json
import socket
import subprocess
import platform
import requests
from rich.console import Console
from rich.table import Table
from datetime import datetime

console = Console()
HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

def resolve_ip(target):
    try:
        ip = socket.gethostbyname(target)
        console.print(f"[green]✓ Resolved {target} to {ip}[/green]")
        return ip
    except Exception as e:
        console.print(f"[red]✘ Failed to resolve IP: {e}[/red]")
        return None

def get_geo_info(ip, proxy=None):
    console.print(f"[cyan]→ Fetching GeoIP info for {ip}[/cyan]")
    try:
        res = requests.get(f"https://ip-api.com/json/{ip}?fields=country,regionName,city,lat,lon,org,as,timezone,zip", 
                            headers=HEADERS, proxies=proxy, timeout=10)
        data = res.json()
        if data.get("status") == "fail":
            console.print("[red]GeoIP lookup failed![/red]")
            return {}
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "organization": data.get("org"),
            "asn": data.get("as"),
            "timezone": data.get("timezone"),
            "postal": data.get("zip")
        }
    except Exception as e:
        console.print(f"[red]GeoIP error: {e}[/red]")
        return {}

def reverse_dns(ip):
    console.print(f"[cyan]→ Performing Reverse DNS lookup on {ip}[/cyan]")
    try:
        host = socket.gethostbyaddr(ip)
        console.print(f"[green]✓ Found: {host[0]}[/green]")
        return host[0]
    except Exception as e:
        console.print(f"[red]Reverse DNS failed: {e}[/red]")
        return "N/A"

def do_ping(ip):
    console.print(f"[cyan]→ Running ping test to {ip}[/cyan]")
    system = platform.system().lower()
    cmd = ["ping", "-c", "4", ip] if system != "windows" else ["ping", ip, "-n", "4"]
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        lines = result.splitlines()
        summary = lines[-2:] if system != "windows" else lines[-4:]
        return "\n".join(summary)
    except Exception as e:
        return f"Ping failed: {e}"

def traceroute(ip):
    console.print(f"[cyan]→ Running traceroute to {ip}[/cyan]")
    system = platform.system().lower()
    cmd = ["traceroute", ip] if system != "windows" else ["tracert", ip]
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        return result
    except Exception as e:
        return f"Traceroute failed: {e}"

def whois_lookup(domain):
    console.print(f"[cyan]→ Running WHOIS lookup for {domain}[/cyan]")
    try:
        res = requests.get(f"https://whois.icann.org/en/lookup?name={domain}", headers=HEADERS, timeout=10)
        match = re.search(r'<pre class="queryOutput">(.*?)</pre>', res.text, re.DOTALL)
        if match:
            content = match.group(1).replace("<br>", "\n").strip()
            return content
        return "WHOIS output not found."
    except Exception as e:
        return f"WHOIS error: {e}"

def get_virustotal_report(ip, api_key, proxy=None):
    console.print(f"[cyan]→ Checking VirusTotal report for {ip}[/cyan]")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        res = requests.get(url, headers=headers, proxies=proxy, timeout=10)
        if res.status_code == 200:
            data = res.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_scans": sum(stats.values())
            }
        return {"error": "Not found or no API key"}
    except Exception as e:
        return {"error": str(e)}

def save_json(data, ip):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/ip_analyze_{ip}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    console.print(f"[green]✔ Data saved to {filename}[/green]")

def run(proxy=None):
    console.rule("[bold cyan]:: ADVANCED IP ANALYZER ::[/bold cyan]", align="center")
    target = input("Enter target domain or IP address: ").strip()

    ip = resolve_ip(target)
    if not ip:
        console.print("[red]✘ Could not resolve IP from target.[/red]")
        return

    domain = target if "." in target and "/" not in target else ip
    whois_data = whois_lookup(domain)

    vt_api = os.getenv("VT_API_KEY")  # Simpan API key di environment variable
    virustotal_data = get_virustotal_report(ip, vt_api, proxy) if vt_api else {"status": "No API key"}

    geoip_data = get_geo_info(ip, proxy)
    rev_dns = reverse_dns(ip)

    ping_result = do_ping(ip)
    trace_result = traceroute(ip)

    result = {
        "target": target,
        "ip_address": ip,
        "geoip": geoip_data,
        "reverse_dns": rev_dns,
        "virustotal": virustotal_data,
        "ping_summary": ping_result,
        "traceroute_raw": trace_result,
        "whois_raw": whois_data,
        "metadata": {
            "scanned_at": datetime.now().isoformat(),
            "tool": "ip_analyzer_pro",
            "version": "v2"
        }
    }

    table = Table(show_header=False, header_style="bold green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="magenta")

    def add_row(field, value):
        if isinstance(value, dict):
            val_str = "\n".join([f"{k}: {v}" for k, v in value.items() if v])
            table.add_row(field, val_str)
        elif isinstance(value, list):
            table.add_row(field, "\n".join(value))
        else:
            table.add_row(field, str(value))

    add_row("Target", target)
    add_row("IP Address", ip)
    add_row("Country", geoip_data.get("country", "N/A"))
    add_row("City", geoip_data.get("city", "N/A"))
    add_row("ISP / Org", geoip_data.get("organization", "N/A"))
    add_row("ASN", geoip_data.get("asn", "N/A"))
    add_row("VirusTotal Malicious", virustotal_data.get("malicious", "N/A"))
    add_row("Ping Summary", ping_result[:100] + "...")
    add_row("Reverse DNS", rev_dns)

    console.print(table)
    save_json(result, ip)

if __name__ == "__main__":
    run()