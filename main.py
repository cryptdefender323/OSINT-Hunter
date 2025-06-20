#!/usr/bin/env python3

import os
from typing import Callable
from rich.console import Console
from rich.prompt import Prompt

console = Console()
os.makedirs("logs", exist_ok=True)

missing = []
try:
    from modules import (
        username_lookup,
        email_breach,
        domain_recon,
        ip_analyzer,
        metadata_extractor,
        url_scanner,
        pastebin_scraper,
        telegram_scraper,
        xss_fuzzer
    )
except ModuleNotFoundError as e:
    missing.append(str(e).split("'")[1])

if missing:
    console.print("\n[bold red]✘ Missing modules detected:[/bold red]")
    for m in missing:
        console.print(f"[yellow]- {m}[/yellow]")
    console.print("\n[bold blue]→ Please install missing dependencies with:[/bold blue]")
    console.print("[green]pip install -r requirements.txt[/green] or manually install them.")
    exit(1)

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def show_banner():
    banner = r"""
 _   _ ____  ____    ____            _     _____ _           _           
| | | |  _ \|  _ \  | __ ) _   _ ___| |_  |_   _(_)_ __ ___ (_)_ __ ___  
| |_| | |_) | |_) | |  _ \| | | / __| __|   | | | | '_ ` _ \| | '_ ` _ \ 
|  _  |  __/|  _ <  | |_) | |_| \__ \ |_    | | | | | | | | | | | | | | |
|_| |_|_|   |_| \_\ |____/ \__,_|___/\__|   |_| |_|_| |_| |_|_|_| |_| |_|
                                                                        
                 CryptDefender V2 • Open Source Intelligence Tool Suite
    """
    console.print(banner, style="bold green")

def pause_return():
    try:
        input("\n[bold blue]→ Press ENTER to return to the main menu...[/bold blue]")
    except KeyboardInterrupt:
        pass
    clear_screen()
    show_banner()

def run_module(name: str, func: Callable):
    try:
        console.print(f"[yellow]↪ Running {name}... (Press Ctrl+C to cancel)[/yellow]")
        func()
    except KeyboardInterrupt:
        console.print(f"\n[red]❌ {name} canceled by user.[/red]")
    except Exception as e:
        console.print(f"[red]✘ Error in module {name}: {e}[/red]")
    finally:
        pause_return()

def show_menu():
    console.print("\n[bold cyan]:: CryptDefender | SELECT A MODULE ::[/bold cyan]")
    console.print("[1] Username Lookup")
    console.print("[2] Email Breach Analyzer")
    console.print("[3] Domain Recon (Whois, DNS)")
    console.print("[4] IP Analyzer (GeoIP, ASN, Ping)")
    console.print("[5] Metadata Extractor")
    console.print("[6] URL Scanner")
    console.print("[7] XSS Param Fuzzer")
    console.print("[8] Pastebin Keyword Scraper")
    console.print("[9] Telegram OSINT Scraper")
    console.print("[99] Exit")

def main():
    while True:
        try:
            clear_screen()
            show_banner()
            show_menu()

            choice = Prompt.ask("\n[bold green]cryptdefender>[/bold green]", default="00")

            if choice == "1":
                run_module("Username Lookup", username_lookup.run)
            elif choice == "2":
                run_module("Email Breach Analyzer", email_breach.run)
            elif choice == "3":
                run_module("Domain Recon", domain_recon.run)
            elif choice == "4":
                run_module("IP Analyzer", ip_analyzer.run)
            elif choice == "5":
                run_module("Metadata Extractor", metadata_extractor.run)
            elif choice == "6":
                run_module("URL Scanner", url_scanner.run)
            elif choice == "7":
                run_module("XSS Param Fuzzer", xss_fuzzer.run)
            elif choice == "8":
                run_module("Pastebin Keyword Scraper", pastebin_scraper.run)
            elif choice == "9":
                run_module("Telegram OSINT Scraper", telegram_scraper.run)
            elif choice == "99":
                console.print("[bold red]Exiting CryptDefender. See you![/bold red]")
                break
            else:
                console.print("[yellow]✘ Invalid input. Select a number from 1 to 9.[/yellow]")
                pause_return()

        except KeyboardInterrupt:
            continue

if __name__ == "__main__":
    main()