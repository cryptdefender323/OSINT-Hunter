#!/usr/bin/env python3

import os, json, sys, hashlib, re, requests, string
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()

HASH_PATTERNS = [
    {"name": "MD5", "length": 32, "regex": r"^[a-fA-F0-9]{32}$"},
    {"name": "SHA-1", "length": 40, "regex": r"^[a-fA-F0-9]{40}$"},
    {"name": "SHA-224", "length": 56, "regex": r"^[a-fA-F0-9]{56}$"},
    {"name": "SHA-256", "length": 64, "regex": r"^[a-fA-F0-9]{64}$"},
    {"name": "SHA-384", "length": 96, "regex": r"^[a-fA-F0-9]{96}$"},
    {"name": "SHA-512", "length": 128, "regex": r"^[a-fA-F0-9]{128}$"},
    {"name": "NTLM", "length": 32, "regex": r"^[a-fA-F0-9]{32}$"},
    {"name": "MySQL 4.1+", "length": 40, "regex": r"^\*[a-fA-F0-9]{40}$"},
    {"name": "bcrypt", "length": 60, "regex": r"^\$2[aby]\$\d{2}\$.{53}$"},
    {"name": "Argon2", "length": None, "regex": r"^\$argon2(i|d|id)\$"},
    {"name": "scrypt", "length": None, "regex": r"^\$scrypt\$"},
    {"name": "PBKDF2", "length": None, "regex": r"^pbkdf2"},
    {"name": "Unix DES", "length": 13, "regex": r"^[a-zA-Z0-9./]{13}$"},
    {"name": "Unix MD5", "length": None, "regex": r"^\$1\$"},
    {"name": "Unix SHA-256", "length": None, "regex": r"^\$5\$"},
    {"name": "Unix SHA-512", "length": None, "regex": r"^\$6\$"},
    {"name": "CRC32", "length": 8, "regex": r"^[a-fA-F0-9]{8}$"},
]

class HashAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": Config.get_random_ua()})

    def identify_hash(self, hash_str):
        hash_str = hash_str.strip()
        matches = []
        for hp in HASH_PATTERNS:
            if re.match(hp["regex"], hash_str):
                matches.append(hp["name"])
        return matches

    def generate_hashes(self, plaintext):
        results = {}
        algos = {
            "MD5": hashlib.md5, "SHA-1": hashlib.sha1,
            "SHA-224": hashlib.sha224, "SHA-256": hashlib.sha256,
            "SHA-384": hashlib.sha384, "SHA-512": hashlib.sha512,
        }
        for name, func in algos.items():
            results[name] = func(plaintext.encode()).hexdigest()
        try:
            import binascii
            results["NTLM"] = hashlib.new('md4', plaintext.encode('utf-16le')).hexdigest()
        except: pass
        return results

    def password_strength(self, password):
        score = 0; feedback = []
        if len(password) >= 8: score += 15
        if len(password) >= 12: score += 10
        if len(password) >= 16: score += 10
        if re.search(r'[a-z]', password): score += 10
        if re.search(r'[A-Z]', password): score += 10
        if re.search(r'[0-9]', password): score += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): score += 15
        if not re.search(r'(.)\1{2,}', password): score += 5
        if not re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd)', password.lower()): score += 5
        common = ["password","123456","qwerty","admin","letmein","welcome","monkey","dragon","master","abc123"]
        if password.lower() not in common: score += 10
        else: feedback.append("Common password!")

        if len(password) < 8: feedback.append("Too short (< 8)")
        if not re.search(r'[A-Z]', password): feedback.append("No uppercase")
        if not re.search(r'[0-9]', password): feedback.append("No numbers")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password): feedback.append("No special chars")

        charset = 0
        if re.search(r'[a-z]', password): charset += 26
        if re.search(r'[A-Z]', password): charset += 26
        if re.search(r'[0-9]', password): charset += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset += 32
        import math
        entropy = len(password) * math.log2(charset) if charset > 0 else 0

        strength = "Very Weak" if score < 30 else ("Weak" if score < 50 else ("Medium" if score < 70 else ("Strong" if score < 90 else "Very Strong")))
        return {"score": min(score, 100), "strength": strength, "entropy_bits": round(entropy, 1), "feedback": feedback, "length": len(password), "charset_size": charset}

    def compare_hashes(self, hash1, hash2):
        return {"match": hash1.strip().lower() == hash2.strip().lower(), "hash1": hash1.strip()[:20] + "...", "hash2": hash2.strip()[:20] + "..."}

    def run_identify(self):
        h = input("  Enter hash to identify: ").strip()
        if not h: console.print("[red]Empty![/red]"); return
        matches = self.identify_hash(h)
        if matches:
            console.print(f"\n[green]  Possible hash types:[/green]")
            for m in matches: console.print(f"    [cyan]• {m}[/cyan]")
        else:
            console.print("[yellow]  Unknown hash type[/yellow]")

        Config.ensure_dirs()
        fn = f"logs/hash_id_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fn, "w") as f: json.dump({"hash": h, "types": matches}, f, indent=2)
        console.print(f"[green]✔ Saved: {fn}[/green]")

    def run_generate(self):
        text = input("  Enter text to hash: ").strip()
        if not text: console.print("[red]Empty![/red]"); return
        hashes = self.generate_hashes(text)
        t = Table(title="Generated Hashes", show_header=True, header_style="bold green")
        t.add_column("Algorithm", style="cyan", width=12); t.add_column("Hash", style="yellow")
        for algo, h in hashes.items(): t.add_row(algo, h)
        console.print(t)

    def run_strength(self):
        pw = input("  Enter password to analyze: ").strip()
        if not pw: console.print("[red]Empty![/red]"); return
        result = self.password_strength(pw)
        sc = "green" if result["score"] >= 70 else ("yellow" if result["score"] >= 40 else "red")
        console.print(Panel(
            f"[{sc}]Strength: {result['strength']} ({result['score']}/100)[/{sc}]\n"
            f"Length: {result['length']}  |  Charset: {result['charset_size']}  |  Entropy: {result['entropy_bits']} bits\n"
            f"{'Feedback: ' + ', '.join(result['feedback']) if result['feedback'] else '[green]No issues found[/green]'}",
            title="Password Analysis", border_style=sc))

    def run_compare(self):
        h1 = input("  Hash 1: ").strip()
        h2 = input("  Hash 2: ").strip()
        result = self.compare_hashes(h1, h2)
        color = "green" if result["match"] else "red"
        console.print(f"[{color}]{'✔ MATCH' if result['match'] else '✘ NO MATCH'}[/{color}]")

def main():
    console.print(Panel("[bold cyan]HASH & PASSWORD ANALYZER — OSINT-Hunter V3[/bold cyan]\n[dim]Identify • Generate • Crack • Strength • Compare[/dim]", border_style="cyan"))
    console.print("\n  [1] Identify hash type")
    console.print("  [2] Generate hashes from text")
    console.print("  [3] Password strength analyzer")
    console.print("  [4] Compare two hashes")
    c = input("\n  Select (1-4): ").strip()
    analyzer = HashAnalyzer()
    if c == "1": analyzer.run_identify()
    elif c == "2": analyzer.run_generate()
    elif c == "3": analyzer.run_strength()
    elif c == "4": analyzer.run_compare()
    else: console.print("[red]Invalid![/red]")

if __name__ == "__main__": main()
