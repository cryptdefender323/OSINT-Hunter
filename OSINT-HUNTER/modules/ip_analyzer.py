import os
import json
import socket
import subprocess
import platform
import requests
from rich.console import Console
from datetime import datetime

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

def resolve_ip(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None

def get_geo_info(ip, proxy=None):
    console.print(f"[cyan]→ Getting GeoIP Info for {ip}[/cyan]")
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", headers=HEADERS, proxies=proxy, timeout=10)
        data = res.json()
        if data["status"] == "success":
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone")
            }
    except Exception as e:
        console.print(f"[red]GeoIP error: {e}[/red]")
    return {}

def reverse_dns(ip):
    console.print("[cyan]→ Performing Reverse DNS Lookup[/cyan]")
    try:
        host = socket.gethostbyaddr(ip)
        return host[0]
    except:
        return "N/A"

def do_ping(ip):
    console.print("[cyan]→ Running ping check...[/cyan]")
    system = platform.system().lower()
    cmd = ["ping", "-c", "4", ip] if system != "windows" else ["ping", ip, "-n", "4"]
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        return result
    except Exception as e:
        return f"Ping failed: {e}"

def traceroute(ip):
    console.print("[cyan]→ Running traceroute...[/cyan]")
    system = platform.system().lower()
    cmd = ["traceroute", ip] if system != "windows" else ["tracert", ip]
    try:
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        return result
    except Exception as e:
        return f"Traceroute failed: {e}"

def save_json(data, ip):
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/ip_analyze_{ip}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    console.print(f"[green]✔ Data saved to {filename}[/green]")

def run(proxy=None):
    try:
        console.print("\n[bold cyan]:: IP ANALYZER MODULE[/bold cyan]")
        target = input("Enter target domain/IP: ").strip()

        ip = resolve_ip(target)
        if not ip:
            console.print("[red]Failed to resolve IP![/red]")
            return

        result = {
            "target": target,
            "ip": ip,
            "geoip": get_geo_info(ip, proxy),
            "reverse_dns": reverse_dns(ip),
            "ping": do_ping(ip),
            "traceroute": traceroute(ip)
        }

        save_json(result, ip)
        console.print("[bold green]✓ IP analysis finished.[/bold green]")
    
    except KeyboardInterrupt:
        console.print("\n[red]❌ Canceled by user (Ctrl+C)[/red]")
