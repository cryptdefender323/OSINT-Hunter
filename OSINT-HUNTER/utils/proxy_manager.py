# utils/proxy_manager.py

import requests, os
from time import sleep
from random import shuffle
from rich.console import Console
from threading import Thread
from queue import Queue

console = Console()
CURRENT_PROXY = None
TOR_MODE = False

def get_proxy():
    return CURRENT_PROXY

def unset_proxy():
    global CURRENT_PROXY, TOR_MODE
    TOR_MODE = False
    CURRENT_PROXY = None
    os.environ.pop("http_proxy", None)
    os.environ.pop("https_proxy", None)
    os.environ.pop("all_proxy", None)

def is_valid_ip(ip):
    if not ip: return False
    ip = ip.strip()
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in ip.split(".")) and ip.count('.') == 3

def is_proxy_alive(proxy_dict):
    try:
        res = requests.get("https://api.ipify.org", proxies=proxy_dict, timeout=4)
        ip = res.text.strip()
        return res.status_code == 200 and is_valid_ip(ip)
    except:
        return False

def get_my_ip(proxy_dict=None):
    urls = [
        "https://api.ipify.org", "https://icanhazip.com",
        "https://checkip.amazonaws.com", "https://httpbin.org/ip"
    ]
    for url in urls:
        try:
            res = requests.get(url, proxies=proxy_dict, timeout=4)
            ip = res.text.strip()
            if res.status_code == 200 and is_valid_ip(ip):
                return ip
        except:
            continue
    return None

def fetch_all_proxies():
    sources = [
        "https://proxylist.geonode.com/api/proxy-list?limit=200&page=1&sort_by=lastChecked&sort_type=desc",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    ]
    proxies = []
    for url in sources:
        try:
            res = requests.get(url, timeout=10)
            if "geonode" in url:
                for item in res.json().get("data", []):
                    ip, port, protos = item.get("ip"), item.get("port"), item.get("protocols", [])
                    if ip and port:
                        proto = "https" if "https" in protos else "http"
                        proxies.append(f"{proto}://{ip}:{port}")
            else:
                for line in res.text.strip().splitlines():
                    if ":" in line:
                        proxies.append(f"http://{line.strip()}")
        except:
            continue
    shuffle(proxies)
    return proxies

def find_fast_proxy_parallel(proxies, max_workers=25):
    q = Queue()
    result = {"proxy": None}

    def worker():
        while not q.empty():
            proxy_url = q.get()
            proxy_dict = {"http": proxy_url, "https": proxy_url}
            if is_proxy_alive(proxy_dict):
                result["proxy"] = proxy_url
                with q.mutex:
                    q.queue.clear()
            q.task_done()

    for proxy in proxies:
        q.put(proxy)

    threads = [Thread(target=worker) for _ in range(max_workers)]
    for t in threads:
        t.daemon = True
        t.start()
    q.join()

    return result["proxy"]

def activate_tor_mode():
    global CURRENT_PROXY, TOR_MODE
    tor_proxy = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
    if is_proxy_alive(tor_proxy):
        os.environ.update({
            "http_proxy": tor_proxy["http"],
            "https_proxy": tor_proxy["https"],
            "all_proxy": tor_proxy["http"]
        })
        CURRENT_PROXY = tor_proxy
        TOR_MODE = True
        console.print("[bold green]✓ TOR Mode active (via 127.0.0.1:9050)[/bold green]")
        ip = get_my_ip(tor_proxy)
        if ip:
            console.print(f"[bold green]→ IP TOR: {ip}[/bold green]")
        return True
    else:
        console.print("[red]✘ Failed to connect to TOR. Make sure TOR service is active.[/red]")
        return False

def activate_stealth_mode(max_test=100, manual_fallback=True, use_tor=False):
    global CURRENT_PROXY
    unset_proxy()

    if use_tor:
        return activate_tor_mode()

    console.print("[cyan]→ Enable stealth mode (Parallel Mode)...[/cyan]")
    proxies = fetch_all_proxies()

    if not proxies:
        console.print("[red]✘ No proxy from any source.[/red]")
        return False

    console.print(f"[yellow]→ Find the fastest proxy from {max_test}candidate...[/yellow]")
    fast_proxy = find_fast_proxy_parallel(proxies[:max_test])

    if fast_proxy:
        proxy_dict = {"http": fast_proxy, "https": fast_proxy}
        CURRENT_PROXY = proxy_dict
        os.environ["http_proxy"] = fast_proxy
        os.environ["https_proxy"] = fast_proxy
        console.print(f"[green]✓ Proxy aktif: {fast_proxy}[/green]")
        ip = get_my_ip(proxy_dict)
        if ip:
            console.print(f"[bold green]→ Your current public IP: {ip}[/bold green]")
        return True

    console.print("[red]⚠ There are no proxies that can be used directly.[/red]")

    if manual_fallback:
        pilih = input("Want to select manual proxy? (y/n): ").strip().lower()
        if pilih == "y":
            for i, proxy in enumerate(proxies[:30]):
                console.print(f"[{i+1}] {proxy}")
            pilihan = input("Select proxy number: ").strip()
            if pilihan.isdigit() and 1 <= int(pilihan) <= 30:
                selected = proxies[int(pilihan) - 1]
                CURRENT_PROXY = {"http": selected, "https": selected}
                os.environ["http_proxy"] = selected
                os.environ["https_proxy"] = selected
                console.print(f"[green]✓ Manual proxy selected: {selected}[/green]")
                return True
            else:
                console.print("[red]Invalid input.[/red]")
    return False

def stealth_decorator(func):
    def wrapper(*args, **kwargs):
        if activate_stealth_mode():
            return func(*args, **kwargs)
        else:
            console.print("[red]✘ Scan cancelled. Stealth mode failed to activate..[/red]")
            return None
    return wrapper
