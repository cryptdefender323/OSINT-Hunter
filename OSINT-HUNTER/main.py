#!/usr/bin/env python3

from rich.console import Console
from rich.prompt import Prompt
import os, requests
from modules import (
    username_lookup,
    email_breach,
    domain_recon,
    ip_analyzer,
    metadata_extractor,
    js_param_scanner,
    pastebin_scraper,
    telegram_scraper,
    xss_fuzzer
)
from utils import proxy_manager

console = Console()

def get_proxy():
    return proxy_manager.get_proxy()

def pause_return():
    try:
        input("\n[bold blue]→ Tekan ENTER untuk kembali ke menu utama...[/bold blue]")
    except:
        pass
    clear_screen()
    show_banner()
    check_ip_status()

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def show_banner():
    banner = r"""
 ██████╗ ██████╗ ██╗   ██╗██████╗ ████████╗██╗  ██╗ ██████╗ ██████╗ ███╗   ███╗
██╔════╝ ██╔══██╗██║   ██║██╔══██╗╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗████╗ ████║
██║  ███╗██████╔╝██║   ██║██████╔╝   ██║   ███████║██║   ██║██████╔╝██╔████╔██║
██║   ██║██╔═══╝ ██║   ██║██╔═══╝    ██║   ██╔══██║██║   ██║██╔═══╝ ██║╚██╔╝██║
╚██████╔╝██║     ╚██████╔╝██║        ██║   ██║  ██║╚██████╔╝██║     ██║ ╚═╝ ██║
 ╚═════╝ ╚═╝      ╚═════╝ ╚═╝        ╚═╝   ╚═╝  ╚═════╝ ╚═╝     ╚═╝     ╚═╝
                            CryptDefender V1 • OSINT TOOLS
    """
    console.print(banner, style="bold green")

def check_ip_status():
    console.print("[cyan]Check active public IP...[/cyan]")
    try:
        ip = requests.get("https://api.ipify.org", proxies=get_proxy(), timeout=5).text.strip()
        console.print(f"[green]✓ Your current IP: {ip}[/green]")
    except:
        console.print("[red]✘ Failed to get IP. Proxy may be down.[/red]")

def show_menu():
    console.print("\n[bold cyan]:: CryptDefender | SELECT A MODULE ::[/bold cyan]")
    console.print("[0] Toggle Proxy (Stealth / TOR / OFF)")
    console.print("[1] Username Lookup")
    console.print("[2] Email Breach Analyzer")
    console.print("[3] Domain Recon (Whois, DNS)")
    console.print("[4] IP Analyzer (GeoIP, ASN, Ping)")
    console.print("[5] Metadata Extractor")
    console.print("[6] JS File + Param Scanner")
    console.print("[7] XSS Param Fuzzer")
    console.print("[8] Pastebin Keyword Scraper")
    console.print("[9] Telegram OSINT Scraper")
    console.print("[99] Exit")

def run_module(name, func, use_proxy=True):
    try:
        console.print(f"[yellow]↪ Running{name}... (Press Ctrl+C to cancel)[/yellow]")
        if use_proxy:
            func(proxy=get_proxy())
        else:
            func()
    except KeyboardInterrupt:
        console.print(f"\n[red]❌ {name} canceled by user.[/red]")
    except Exception as e:
        console.print(f"[red]✘ Error in module {name}: {e}[/red]")
    finally:
        pause_return()

def toggle_proxy():
    if proxy_manager.get_proxy():
        proxy_manager.unset_proxy()
        console.print("[red]✘ Proxy dinonaktifkan.[/red]")
    else:
        console.print("\n[cyan]Select stealth mode:[/cyan]")
        console.print("[1] Proxy Mode (Auto-Rotate Proxy)")
        console.print("[2] TOR Mode (via 127.0.0.1:9050)")
        mode = Prompt.ask("Select mode", choices=["1", "2"], default="1")
        if mode == "1":
            proxy_manager.activate_stealth_mode()
        else:
            proxy_manager.activate_stealth_mode(use_tor=True)

def main():
    os.makedirs("logs", exist_ok=True)
    while True:
        try:
            clear_screen()
            show_banner()
            check_ip_status()
            show_menu()
            choice = Prompt.ask("\n[bold green]crypthecom>[/bold green]", default="00")

            if choice == "0":
                toggle_proxy()
                pause_return()
            elif choice == "1":
                run_module("Username Lookup", username_lookup.run)
            elif choice == "2":
                run_module("Email Breach Analyzer", email_breach.run)
            elif choice == "3":
                run_module("Domain Recon", domain_recon.run)
            elif choice == "4":
                run_module("IP Analyzer", ip_analyzer.run)
            elif choice == "5":
                run_module("Metadata Extractor", metadata_extractor.run, use_proxy=False)
            elif choice == "6":
                run_module("JS File + Param Scanner", js_param_scanner.run)
            elif choice == "7":
                run_module("XSS Param Fuzzer", xss_fuzzer.run)
            elif choice == "8":
                run_module("Pastebin Keyword Scraper", pastebin_scraper.run)
            elif choice == "9":
                run_module("Telegram OSINT Scraper", telegram_scraper.run)
            elif choice == "99":
                console.print("[bold red]Exit CryptDefender. See you![/bold red]")
                break
            else:
                console.print("[yellow]✘ Invalid input. Select a number from 0 to 9.[/yellow]")
                pause_return()

        except KeyboardInterrupt:
            continue 

if __name__ == "__main__":
    main()
