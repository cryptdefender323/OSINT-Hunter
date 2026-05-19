#!/usr/bin/env python3

import os, sys, importlib

try:
    from rich.console import Console
    from rich.prompt import Prompt
    from rich.panel import Panel
except ImportError:
    print("[!] Dependencies missing. Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()
os.makedirs("logs", exist_ok=True)
os.makedirs("results", exist_ok=True)


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def show_banner():
    banner = r"""
   ____  ____ ___ _   _ _____   _   _ _   _ _   _ _____ _____ ____
  / __ \/ ___|_ _| \ | |_   _| | | | | | | | \ | |_   _| ____|  _ \
 | |  | \___ \| ||  \| | | |   | |_| | | | |  \| | | | |  _| | |_) |
 | |__| |___) | || |\  | | |   |  _  | |_| | |\  | | | | |___|  _ <
  \____/|____/___|_| \_| |_|   |_| |_|\___/|_| \_| |_| |_____|_| \_\
    """
    console.print(banner, style="bold cyan")
    console.print(
        Panel(
            "[bold white]OSINT-Hunter V3[/bold white]  •  "
            "[dim]Open Source Intelligence Toolkit[/dim]\n"
            "[dim]For authorized security research and educational use only[/dim]",
            border_style="cyan",
            expand=False,
        )
    )


def show_menu():
    console.print("\n[bold cyan]── MODULES ──────────────────────────────────[/bold cyan]")
    console.print(" [bold]Reconnaissance[/bold]")
    console.print("  [1]  Username Lookup          — 55+ platforms, confidence scoring")
    console.print("  [2]  Email Breach Analyzer     — HIBP, EmailRep, Hunter.io")
    console.print("  [3]  Domain Recon              — WHOIS, DNS, subdomains, SSL, tech stack")
    console.print("  [4]  IP Analyzer               — GeoIP, Shodan, VirusTotal, port scan")
    console.print("  [5]  Phone Lookup              — Carrier, location, type, risk")
    console.print("  [6]  Username OSINT            — GitHub, Reddit, Keybase, HN (API-only)")
    console.print()
    console.print(" [bold]Threat Intelligence[/bold]")
    console.print("  [7]  Breach Aggregator         — HIBP, LeakCheck, IntelX, DeHashed")
    console.print("  [8]  Network Vuln Scanner      — Ports, SSL/TLS, CORS, CVE lookup")
    console.print("  [9]  Hash & Password Analyzer  — Identify, generate, strength check")
    console.print("  [10] URL Scanner               — Phishing, VirusTotal, Safe Browsing")
    console.print()
    console.print(" [bold]Analysis & Extraction[/bold]")
    console.print("  [11] XSS Param Fuzzer          — WAF detection, encoded payloads")
    console.print("  [12] Metadata Extractor        — PDF, DOCX, images, audio/video")
    console.print("  [13] Pastebin Leak Scanner     — psbdmp.ws, GitHub Gist")
    console.print("  [14] Telegram OSINT            — Members, messages, activity")
    console.print("  [15] Name / Keyword Scraper    — Search engines + GitHub deep search")
    console.print()
    console.print("  [99] Exit")
    console.print("[bold cyan]─────────────────────────────────────────────[/bold cyan]")


MODULES = {
    "1":  ("username_lookup",     "Username Lookup"),
    "2":  ("email_breach",        "Email Breach Analyzer"),
    "3":  ("domain_recon",        "Domain Recon"),
    "4":  ("ip_analyzer",         "IP Analyzer"),
    "5":  ("phone_lookup",        "Phone Lookup"),
    "6":  ("username_osint",      "Username OSINT"),
    "7":  ("breach_aggregator",   "Breach Aggregator"),
    "8":  ("network_vuln_scanner","Network Vuln Scanner"),
    "9":  ("hash_analyzer",       "Hash & Password Analyzer"),
    "10": ("url_scanner",         "URL Scanner"),
    "11": ("xss_fuzzer",          "XSS Param Fuzzer"),
    "12": ("metadata_extractor",  "Metadata Extractor"),
    "13": ("pastebin_scraper",    "Pastebin Leak Scanner"),
    "14": ("telegram_scraper",    "Telegram OSINT"),
    "15": ("name_scraper",        "Name / Keyword Scraper"),
}


def run_module(mod_name, label):
    try:
        mod = importlib.import_module(f"modules.{mod_name}")
        console.print(f"\n[yellow]↪ {label}  (Ctrl+C to cancel)[/yellow]\n")
        if hasattr(mod, "main"):
            mod.main()
        elif hasattr(mod, "run"):
            mod.run()
        else:
            console.print(f"[red]✘ Module '{mod_name}' has no main() or run() entry point[/red]")
    except ImportError as e:
        console.print(f"[red]✘ Import error in {mod_name}: {e}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]↩ Cancelled[/yellow]")
    except Exception as e:
        console.print(f"[red]✘ Error in {mod_name}: {e}[/red]")
    finally:
        try:
            input("\n→ Press ENTER to return to menu...")
        except (KeyboardInterrupt, EOFError):
            pass


def main():
    while True:
        try:
            clear()
            show_banner()
            show_menu()

            choice = Prompt.ask("\n[bold green]osint-hunter>[/bold green]", default="")

            if choice == "99":
                console.print("\n[bold cyan]Goodbye.[/bold cyan]\n")
                break
            elif choice in MODULES:
                mod_name, label = MODULES[choice]
                run_module(mod_name, label)
            elif choice == "":
                pass
            else:
                console.print("[yellow]Invalid choice. Enter a number from 1–15 or 99 to exit.[/yellow]")
                try:
                    input("→ Press ENTER...")
                except (KeyboardInterrupt, EOFError):
                    pass

        except KeyboardInterrupt:
            continue


if __name__ == "__main__":
    main()
