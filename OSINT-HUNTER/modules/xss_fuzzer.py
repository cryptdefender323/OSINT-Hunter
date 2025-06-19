#!/usr/bin/env python3

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import argparse
import concurrent.futures
import signal
import sys
import os
import webbrowser


class XSSScanner:
    def __init__(self, base_url, payloads):
        self.base_url = base_url
        self.payloads = payloads
        self.visited = set()
        self.results = []
        os.makedirs("logs", exist_ok=True)
        self.log_file = open("logs/xss_results.txt", "w")

    def crawl(self, url):
        if url in self.visited:
            return
        self.visited.add(url)
        try:
            res = requests.get(url, timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            for tag in soup.find_all(['a', 'form'], href=True):
                next_url = urljoin(url, tag.get('href'))
                if self.base_url in next_url:
                    self.crawl(next_url)
        except:
            pass

    def extract_params(self, url):
        return list(parse_qs(urlparse(url).query).keys())

    def inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def encode_payload(self, payload):
        waf_bypass = [
            payload,
            payload.replace('<', '%3C').replace('>', '%3E').replace('"', '%22'),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('script', 'scr\u0069pt'),
            payload.replace('alert', '\u0061lert'),
            payload.replace('(', '%28').replace(')', '%29'),
            ''.join(['&#{};'.format(ord(c)) for c in payload]),
        ]
        return list(set(waf_bypass))

    def detect_xss(self, url):
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            xss_triggered = False

            def on_dialog(dialog):
                nonlocal xss_triggered
                xss_triggered = True
                dialog.dismiss()

            page.on("dialog", on_dialog)
            try:
                page.goto(url, timeout=8000)
            except:
                pass

            try:
                page.evaluate("document.body.innerHTML += '<div id=\"domxss\">XSS</div>';")
                if page.query_selector('#domxss'):
                    xss_triggered = True
            except:
                pass

            browser.close()
            return xss_triggered

    def test_url(self, url):
        params = self.extract_params(url)
        for param in params:
            for p in self.payloads:
                for encoded in self.encode_payload(p):
                    test_url = self.inject_payload(url, param, encoded)
                    if self.detect_xss(test_url):
                        self.results.append((test_url, encoded))
                        print(f"[✔] XSS Detected: \033[94m{test_url}\033[0m | Payload: {encoded}")
                        self.log_file.write(f"[✔] {test_url} | {encoded}\n")
                    else:
                        print(f"[✘] No XSS: {test_url} | Payload: {encoded}")
                        self.log_file.write(f"[✘] {test_url} | {encoded}\n")

    def run(self):
        print("[*] Crawling for URLs...")
        self.crawl(self.base_url)
        print(f"[*] Testing {len(self.visited)} URLs...")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                executor.map(self.test_url, self.visited)
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
        finally:
            self.log_file.close()
            print("[*] Scan finished. Results saved in logs/xss_results.txt")

            if self.results:
                print("\n[!] Triggered XSS URLs (clickable):")
                for res in self.results:
                    print(f" → \033]8;;{res[0]}\033\\{res[0]}\033]8;;\033\\")
            else:
                print("[-] No XSS found.")

            try:
                input("\n[bold blue]→ Press ENTER to return to the main menu...[/bold blue]\n")
            except KeyboardInterrupt:
                pass


def run():
    print("[*] Running XSS Fuzzer module (Press CTRL+C to cancel)...")
    url = input("Target URL (e.g. https://target.com/search?q=): ").strip()
    payload_path = input("Path to payload file (e.g. XSS_Payload.txt): ").strip()

    if not url or not payload_path:
        print("[!] URL and payload path required.")
        return

    if payload_path.startswith("http"):
        payloads = requests.get(payload_path).text.splitlines()
    else:
        with open(payload_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]

    scanner = XSSScanner(url, payloads)
    scanner.run()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
    parser.add_argument('url', help='Target URL (with http/https)', nargs='?')
    parser.add_argument('-p', '--payloads', help='Payload list file or URL')
    args = parser.parse_args()

    if args.url and args.payloads:
        if args.payloads.startswith('http'):
            payloads = requests.get(args.payloads).text.splitlines()
        else:
            with open(args.payloads, 'r') as f:
                payloads = [line.strip() for line in f if line.strip()]

        scanner = XSSScanner(args.url, payloads)
        scanner.run()
    else:
        run()
