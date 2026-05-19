#!/usr/bin/env python3

import os
from dotenv import load_dotenv

load_dotenv()


class Config:

    # Telegram
    TELEGRAM_API_ID = os.getenv("TELEGRAM_API_ID", "")
    TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "")
    TELEGRAM_PHONE = os.getenv("TELEGRAM_PHONE", "")
    TELEGRAM_SESSION = os.getenv("SESSION_NAME", "telegram_osint")

    # VirusTotal
    VT_API_KEY = os.getenv("VT_API_KEY", "")

    # Shodan
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

    # Google Safe Browsing
    GSB_API_KEY = os.getenv("GSB_API_KEY", "")

    # Have I Been Pwned
    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

    # Hunter.io
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")

    # SecurityTrails
    SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")

    # AbuseIPDB
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

    # URLScan.io
    URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")

    # NumVerify (phone lookup)
    NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")

    # EmailRep.io
    EMAILREP_API_KEY = os.getenv("EMAILREP_API_KEY", "")

    # LeakCheck.io (breach_aggregator)
    LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY", "")

    # IntelX / intelligence.x (breach_aggregator)
    INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")

    # DeHashed (breach_aggregator) — also needs DEHASHED_EMAIL
    DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")
    DEHASHED_EMAIL = os.getenv("DEHASHED_EMAIL", "")

    # Twitter/X Bearer Token (username_osint)
    TWITTER_BEARER_TOKEN = os.getenv("TWITTER_BEARER_TOKEN", "")

    # Proxy
    PROXY = os.getenv("PROXY_URL", "")

    # Output
    LOG_DIR = "logs"
    RESULT_DIR = "results"

    # User Agent Pool
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    ]

    @classmethod
    def get_proxy_dict(cls):
        if cls.PROXY:
            return {"http": cls.PROXY, "https": cls.PROXY}
        return None

    @classmethod
    def get_random_ua(cls):
        import random
        return random.choice(cls.USER_AGENTS)

    @classmethod
    def ensure_dirs(cls):
        os.makedirs(cls.LOG_DIR, exist_ok=True)
        os.makedirs(cls.RESULT_DIR, exist_ok=True)

    @classmethod
    def check_api_keys(cls):
        keys = {
            "VirusTotal": cls.VT_API_KEY,
            "Shodan": cls.SHODAN_API_KEY,
            "HIBP": cls.HIBP_API_KEY,
            "Hunter.io": cls.HUNTER_API_KEY,
            "SecurityTrails": cls.SECURITYTRAILS_API_KEY,
            "AbuseIPDB": cls.ABUSEIPDB_API_KEY,
            "URLScan.io": cls.URLSCAN_API_KEY,
            "NumVerify": cls.NUMVERIFY_API_KEY,
            "EmailRep": cls.EMAILREP_API_KEY,
            "Google Safe Browsing": cls.GSB_API_KEY,
        }
        configured = {}
        missing = {}
        for name, val in keys.items():
            if val:
                configured[name] = True
            else:
                missing[name] = False
        return configured, missing
