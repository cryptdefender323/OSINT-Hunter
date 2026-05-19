# OSINT-Hunter V3

A modular, API-first open source intelligence toolkit built for security researchers, bug bounty hunters, and CTF players.

Each module is self-contained and can be run standalone or through the interactive menu.

---

## Modules

### Reconnaissance

| # | Module | Description |
|---|--------|-------------|
| 1 | **Username Lookup** | Checks 55+ platforms with confidence scoring and HTML report export |
| 2 | **Email Breach Analyzer** | HIBP v3, EmailRep, Hunter.io, MX/SPF/DMARC validation |
| 3 | **Domain Recon** | WHOIS, DNS records, subdomain enumeration (crt.sh, Anubis, SecurityTrails), SSL info, HTTP security headers, tech fingerprinting, subdomain takeover detection, Wayback URLs |
| 4 | **IP Analyzer** | GeoIP (ip-api + ipinfo), reverse DNS, port scan, Shodan, VirusTotal, AbuseIPDB, Tor exit node detection, threat scoring |
| 5 | **Phone Lookup** | Carrier, country, number type, timezone, NumVerify, risk scoring |
| 6 | **Username OSINT** | API-only lookup across GitHub, Reddit, Twitter/X, Mastodon, Keybase, HackerNews, Dev.to, npm, PyPI — with cross-platform correlation |

### Threat Intelligence

| # | Module | Description |
|---|--------|-------------|
| 7 | **Breach Aggregator** | Credential exposure check via HIBP, PwnedPasswords (k-anonymity), LeakCheck.io, IntelX, DeHashed — API-only, no scraping |
| 8 | **Network Vuln Scanner** | Port scan, SSL/TLS version check, HTTP security headers scoring, CORS misconfiguration, CVE lookup, tech fingerprinting |
| 9 | **Hash & Password Analyzer** | Hash type identification, hash generation, password strength + entropy analysis |
| 10 | **URL Scanner** | Phishing signal detection, redirect chain analysis, VirusTotal, Google Safe Browsing, URLScan.io, page content analysis |

### Analysis & Extraction

| # | Module | Description |
|---|--------|-------------|
| 11 | **XSS Param Fuzzer** | WAF detection, payload encoding variants, DOM/reflected XSS detection, auto-crawl |
| 12 | **Metadata Extractor** | Extracts metadata and sensitive data patterns from PDF, DOCX, XLSX, PPTX, images (EXIF + GPS), audio/video |
| 13 | **Pastebin Leak Scanner** | Searches psbdmp.ws and GitHub Gist for keywords, extracts emails, API keys, JWTs, connection strings |
| 14 | **Telegram OSINT** | Scrapes group members, contacts, and messages using Telethon (requires Telegram API credentials) |
| 15 | **Name / Keyword Scraper** | Deep search across DuckDuckGo, Bing, Yahoo, GitHub API, and dev platforms |

---

## API Keys

All API keys are optional. Modules degrade gracefully — if a key is missing, that source is skipped and clearly labelled in the output.

| Key | Used by | Free tier |
|-----|---------|-----------|
| `HIBP_API_KEY` | Email Breach, Breach Aggregator | Paid ($3.50/month) |
| `VT_API_KEY` | IP Analyzer, URL Scanner | 500 req/day |
| `SHODAN_API_KEY` | IP Analyzer | Limited free |
| `ABUSEIPDB_API_KEY` | IP Analyzer | 1,000 req/day |
| `SECURITYTRAILS_API_KEY` | Domain Recon | 50 req/month |
| `URLSCAN_API_KEY` | URL Scanner | Free |
| `GSB_API_KEY` | URL Scanner | Free |
| `HUNTER_API_KEY` | Email Breach | 25 req/month |
| `EMAILREP_API_KEY` | Email Breach | Free |
| `NUMVERIFY_API_KEY` | Phone Lookup | 100 req/month |
| `LEAKCHECK_API_KEY` | Breach Aggregator | Paid |
| `INTELX_API_KEY` | Breach Aggregator | Free (limited) |
| `DEHASHED_API_KEY` + `DEHASHED_EMAIL` | Breach Aggregator | Paid |
| `TWITTER_BEARER_TOKEN` | Username OSINT | Free (Basic tier) |
| `TELEGRAM_API_ID` + `TELEGRAM_API_HASH` + `TELEGRAM_PHONE` | Telegram OSINT | Free |

---

## Installation

```bash
git clone https://github.com/your-username/osint-hunter
cd osint-hunter
pip install -r requirements.txt
```

Copy the example env file and fill in your API keys:

```bash
cp .env.example .env
```

Run:

```bash
python3 main.py
```

Or run any module standalone:

```bash
python3 modules/domain_recon.py
python3 modules/breach_aggregator.py
```

---

## Output

All results are saved automatically:

- `logs/` — JSON reports for every scan
- `results/` — HTML reports (Username Lookup) and CSV exports (Telegram OSINT)

---

## Requirements

- Python 3.10+
- See `requirements.txt` for full dependency list

Tested on Linux (Kali, Parrot, Ubuntu), macOS, and Windows (WSL).

---

## Legal

This tool is intended for **authorized security testing, bug bounty research, and educational purposes only**.

- Only use against targets you own or have explicit written permission to test
- The author is not responsible for any misuse or damage caused by this tool
- Usage may be subject to local laws — ensure compliance before use

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
