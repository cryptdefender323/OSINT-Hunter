#!/usr/bin/env python3

import os
import csv
import asyncio
import re
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
from datetime import datetime
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config

console = Console()

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from telethon import TelegramClient, functions, types
    from telethon.errors import SessionPasswordNeededError
    HAS_TELETHON = True
except ImportError:
    HAS_TELETHON = False


class TelegramScraper:
    def __init__(self):
        self.api_id = int(Config.TELEGRAM_API_ID) if Config.TELEGRAM_API_ID else None
        self.api_hash = Config.TELEGRAM_API_HASH
        self.phone = Config.TELEGRAM_PHONE
        self.session_name = Config.TELEGRAM_SESSION
        self.profiles = []
        self.messages_found = []
        self.seen = set()
        self.client = None

    async def connect(self):
        if not HAS_TELETHON:
            console.print("[red]✘ Telethon not installed. Run: pip install telethon[/red]")
            return False

        if not self.api_id or not self.api_hash:
            console.print("[red]✘ Telegram API credentials not configured in .env[/red]")
            return False

        self.client = TelegramClient(self.session_name, self.api_id, self.api_hash)
        console.print("[cyan]→ Connecting to Telegram...[/cyan]")
        await self.client.start(self.phone)

        if not await self.client.is_user_authorized():
            await self.client.send_code_request(self.phone)
            try:
                code = input("  Enter the code sent via Telegram: ").strip()
                await self.client.sign_in(self.phone, code)
            except SessionPasswordNeededError:
                password = input("  Enter your 2FA password: ").strip()
                await self.client.sign_in(password=password)

        me = await self.client.get_me()
        console.print(f"[green]  ✔ Logged in as: {me.first_name} (@{me.username})[/green]")
        return True

    async def get_user_bio(self, user):
        try:
            full = await self.client(functions.users.GetFullUserRequest(user))
            return full.full_user.about or ""
        except Exception:
            return ""

    def _format_status(self, user):
        if not hasattr(user, 'status') or not user.status:
            return "Unknown"
        status = user.status
        status_type = type(status).__name__
        status_map = {
            "UserStatusOnline": "🟢 Online",
            "UserStatusOffline": f"⚫ Offline",
            "UserStatusRecently": "🟡 Recently",
            "UserStatusLastWeek": "🔵 Last Week",
            "UserStatusLastMonth": "⚪ Last Month",
        }
        return status_map.get(status_type, status_type)

    async def scrape_contacts(self):
        console.print("[cyan]→ Fetching contacts...[/cyan]")
        try:
            result = await self.client(functions.contacts.GetContactsRequest(hash=0))
            users = result.users
            for user in users:
                uid = user.username or str(user.id)
                if uid in self.seen:
                    continue
                self.seen.add(uid)
                bio = await self.get_user_bio(user)
                self.profiles.append({
                    "source": "Contact",
                    "user_id": user.id,
                    "username": user.username or "(none)",
                    "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                    "phone": user.phone or "(hidden)",
                    "status": self._format_status(user),
                    "bio": bio[:150],
                    "is_bot": user.bot if hasattr(user, 'bot') else False,
                    "is_premium": user.premium if hasattr(user, 'premium') else False,
                })
            console.print(f"[green]  ✔ Found {len(users)} contacts[/green]")
        except Exception as e:
            console.print(f"[red]  Error fetching contacts: {e}[/red]")

    async def scrape_groups(self):
        console.print("[cyan]→ Scanning groups and channels...[/cyan]")
        group_count = 0
        try:
            async for dialog in self.client.iter_dialogs():
                entity = dialog.entity
                if hasattr(entity, 'megagroup') or hasattr(entity, 'participants_count'):
                    if hasattr(entity, 'participants_count') and entity.participants_count:
                        group_count += 1
                        try:
                            participants = await self.client.get_participants(entity, limit=100)
                            for user in participants:
                                uid = user.username or str(user.id)
                                if uid in self.seen:
                                    continue
                                self.seen.add(uid)
                                bio = await self.get_user_bio(user)
                                self.profiles.append({
                                    "source": dialog.name,
                                    "user_id": user.id,
                                    "username": user.username or "(none)",
                                    "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                                    "phone": user.phone or "(hidden)",
                                    "status": self._format_status(user),
                                    "bio": bio[:150],
                                    "is_bot": user.bot if hasattr(user, 'bot') else False,
                                    "is_premium": user.premium if hasattr(user, 'premium') else False,
                                })
                        except Exception as e:
                            console.print(f"[yellow]  ⚠ Can't access members of '{dialog.name}': {e}[/yellow]")
            console.print(f"[green]  ✔ Scanned {group_count} groups[/green]")
        except Exception as e:
            console.print(f"[red]  Error scanning groups: {e}[/red]")

    async def scrape_specific_group(self, group_link):
        try:
            group = await self.client.get_entity(group_link)
            console.print(f"[cyan]→ Scraping: {group.title}[/cyan]")
            count = 0
            async for user in self.client.iter_participants(group, limit=200):
                uid = user.username or str(user.id)
                if uid in self.seen:
                    continue
                self.seen.add(uid)
                bio = await self.get_user_bio(user)
                self.profiles.append({
                    "source": group.title,
                    "user_id": user.id,
                    "username": user.username or "(none)",
                    "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                    "phone": user.phone or "(hidden)",
                    "status": self._format_status(user),
                    "bio": bio[:150],
                    "is_bot": user.bot if hasattr(user, 'bot') else False,
                    "is_premium": user.premium if hasattr(user, 'premium') else False,
                })
                count += 1
            console.print(f"[green]  ✔ Scraped {count} members from {group.title}[/green]")
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")

    async def search_messages(self, keyword, group_link=None):
        console.print(f"[cyan]→ Searching messages for '{keyword}'...[/cyan]")
        try:
            if group_link:
                entity = await self.client.get_entity(group_link)
                async for msg in self.client.iter_messages(entity, search=keyword, limit=50):
                    sender_name = ""
                    if msg.sender:
                        sender_name = getattr(msg.sender, 'first_name', '') or getattr(msg.sender, 'title', '') or str(msg.sender_id)
                    self.messages_found.append({
                        "group": entity.title if hasattr(entity, 'title') else str(entity.id),
                        "sender": sender_name,
                        "date": msg.date.isoformat() if msg.date else "",
                        "text": msg.text[:300] if msg.text else "(media)",
                        "has_media": msg.media is not None,
                        "message_id": msg.id,
                    })
            else:
                async for dialog in self.client.iter_dialogs(limit=20):
                    try:
                        async for msg in self.client.iter_messages(dialog.entity, search=keyword, limit=10):
                            sender_name = ""
                            if msg.sender:
                                sender_name = getattr(msg.sender, 'first_name', '') or str(msg.sender_id)
                            self.messages_found.append({
                                "group": dialog.name,
                                "sender": sender_name,
                                "date": msg.date.isoformat() if msg.date else "",
                                "text": msg.text[:300] if msg.text else "(media)",
                                "has_media": msg.media is not None,
                                "message_id": msg.id,
                            })
                    except Exception:
                        continue

            console.print(f"[green]  ✔ Found {len(self.messages_found)} matching messages[/green]")
        except Exception as e:
            console.print(f"[red]  Message search error: {e}[/red]")

    def display_profiles(self):
        if not self.profiles:
            console.print("[yellow]  No profiles found[/yellow]")
            return

        table = Table(title=f"Telegram Profiles ({len(self.profiles)})", show_header=True, header_style="bold green")
        table.add_column("Source", style="white", width=15)
        table.add_column("Username", style="cyan", width=15)
        table.add_column("Name", style="magenta", width=18)
        table.add_column("Phone", style="yellow", width=15)
        table.add_column("Status", width=12)
        table.add_column("Bio", style="dim", width=25)

        for prof in self.profiles[:50]:
            table.add_row(
                prof["source"][:15],
                prof["username"],
                prof["name"][:18],
                prof["phone"],
                prof["status"],
                prof["bio"][:25]
            )

        console.print(table)
        if len(self.profiles) > 50:
            console.print(f"[dim]  ... showing 50 of {len(self.profiles)} profiles[/dim]")

    def display_messages(self):
        if not self.messages_found:
            return

        msg_table = Table(title=f"Message Results ({len(self.messages_found)})", show_header=True, header_style="bold blue")
        msg_table.add_column("Group", style="cyan", width=15)
        msg_table.add_column("Sender", style="yellow", width=12)
        msg_table.add_column("Date", style="magenta", width=12)
        msg_table.add_column("Message", style="white")

        for msg in self.messages_found[:30]:
            msg_table.add_row(
                msg["group"][:15],
                msg["sender"][:12],
                msg["date"][:10] if msg["date"] else "—",
                msg["text"][:60]
            )
        console.print(msg_table)

    def save_results(self):
        Config.ensure_dirs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if self.profiles:
            csv_file = f"logs/telegram_profiles_{timestamp}.csv"
            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=self.profiles[0].keys())
                writer.writeheader()
                writer.writerows(self.profiles)
            console.print(f"[green]  ✔ CSV saved: {csv_file}[/green]")

        json_file = f"logs/telegram_osint_{timestamp}.json"
        data = {
            "scan_time": datetime.now().isoformat(),
            "total_profiles": len(self.profiles),
            "total_messages": len(self.messages_found),
            "profiles": self.profiles,
            "messages": self.messages_found,
        }
        with open(json_file, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        console.print(f"[green]  ✔ JSON saved: {json_file}[/green]")

    async def run_async(self):
        console.print(Panel(
            "[bold cyan]TELEGRAM OSINT SCRAPER — OSINT-Hunter V3[/bold cyan]\n"
            "[dim]Contacts • Groups • Members • Message Search • Activity Analysis[/dim]",
            border_style="cyan"
        ))

        connected = await self.connect()
        if not connected:
            return

        console.print("\n  [bold]Options:[/bold]")
        console.print("  [1] Full scan (contacts + all groups)")
        console.print("  [2] Scan specific group")
        console.print("  [3] Search messages by keyword")
        console.print("  [4] Full scan + message search")

        choice = input("\n  Select (1-4): ").strip()

        if choice in ["1", "4"]:
            await self.scrape_contacts()
            await self.scrape_groups()

        if choice == "2":
            group_link = input("  Enter group link or username: ").strip()
            if group_link:
                await self.scrape_specific_group(group_link)

        if choice in ["3", "4"]:
            keyword = input("  Enter search keyword: ").strip()
            if keyword:
                group_link = input("  Specific group link (leave blank for all): ").strip() or None
                await self.search_messages(keyword, group_link)

        self.display_profiles()
        self.display_messages()

        bots = sum(1 for p in self.profiles if p.get("is_bot"))
        premium = sum(1 for p in self.profiles if p.get("is_premium"))
        console.print(Panel(
            f"[bold]Profiles:[/bold] {len(self.profiles)}  |  "
            f"[bold]Bots:[/bold] {bots}  |  "
            f"[bold]Premium:[/bold] {premium}  |  "
            f"[bold]Messages:[/bold] {len(self.messages_found)}",
            title="Telegram OSINT Summary",
            border_style="blue"
        ))

        self.save_results()
        await self.client.disconnect()


def main():
    scraper = TelegramScraper()
    asyncio.run(scraper.run_async())


if __name__ == "__main__":
    main()
