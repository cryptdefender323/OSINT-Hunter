#!/usr/bin/env python3

import os
import csv
import asyncio
from dotenv import load_dotenv
from telethon.sync import TelegramClient
from telethon.errors import SessionPasswordNeededError
from rich.console import Console
from rich.table import Table

console = Console()
load_dotenv()

API_ID = int(os.getenv("TELEGRAM_API_ID"))
API_HASH = os.getenv("TELEGRAM_API_HASH")
PHONE_NUMBER = os.getenv("TELEGRAM_PHONE")
SESSION_NAME = "telegram_osint"

client = TelegramClient(SESSION_NAME, API_ID, API_HASH)


def save_csv(profiles, filename="telegram_profiles.csv"):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["source", "username", "name", "phone", "status"])
        writer.writeheader()
        for prof in profiles:
            writer.writerow(prof)


async def main():
    console.print("[cyan]✔ Attempting to login to Telegram...[/cyan]")
    await client.start(PHONE_NUMBER)

    if not await client.is_user_authorized():
        await client.send_code_request(PHONE_NUMBER)
        try:
            code = input("[?] Enter the code sent via Telegram: ").strip()
            await client.sign_in(PHONE_NUMBER, code)
        except SessionPasswordNeededError:
            password = input("[?] Enter your 2FA password: ").strip()
            await client.sign_in(password=password)

    profiles = []
    seen = set()

    console.print("[yellow]↪ Fetching all contacts...[/yellow]")
    contacts = await client.get_contacts()
    for user in contacts:
        uid = user.username or user.phone or "?"
        if uid in seen:
            continue
        seen.add(uid)
        profiles.append({
            "source": "Contact",
            "username": user.username or "(no username)",
            "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
            "phone": user.phone or "(hidden)",
            "status": str(user.status) if hasattr(user, 'status') else "N/A"
        })

    console.print("[yellow]↪ Scanning all groups/channels from your dialog list...[/yellow]")
    async for dialog in client.iter_dialogs():
        entity = dialog.entity
        if hasattr(entity, 'participants_count') and entity.participants_count:
            try:
                participants = await client.get_participants(entity)
                for user in participants:
                    uid = user.username or user.phone or "?"
                    if uid in seen:
                        continue
                    seen.add(uid)
                    profiles.append({
                        "source": f"{dialog.name}",
                        "username": user.username or "(no username)",
                        "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                        "phone": user.phone or "(hidden)",
                        "status": str(user.status) if hasattr(user, 'status') else "N/A"
                    })
            except:
                continue

    if profiles:
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Source", style="white")
        table.add_column("Username", style="cyan")
        table.add_column("Name", style="magenta")
        table.add_column("Phone", style="yellow")
        table.add_column("Status", style="blue")

        for prof in profiles:
            table.add_row(
                prof["source"], prof["username"], prof["name"], prof["phone"], prof["status"]
            )

        console.print(table)
        save_csv(profiles)
        console.print("[green]✔ Data saved to telegram_profiles.csv[/green]")
    else:
        console.print("[red]❌ No data found.[/red]")


def run():
    with client:
        client.loop.run_until_complete(main())


if __name__ == "__main__":
    run()
