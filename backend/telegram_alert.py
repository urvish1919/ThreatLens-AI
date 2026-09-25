"""
telegram_alert.py

Sends you a free Telegram message. No card, no cost, no limits that matter
for personal use.

SETUP (do this once, takes ~3 minutes):
1. Open Telegram, search for "BotFather", start a chat with it.
2. Send: /newbot
3. Follow the prompts (give it any name) — BotFather gives you a TOKEN
   that looks like: 123456789:ABCdefGhIJKlmNoPQRstuVwXyz
4. Save that token in your .env as TELEGRAM_BOT_TOKEN
5. To get your CHAT ID: search for "userinfobot" on Telegram, start it,
   it instantly replies with your numeric chat ID. Save that as
   TELEGRAM_CHAT_ID in your .env.
6. Send your new bot ANY message first (e.g. "hi") — Telegram bots can't
   message you until you've messaged them at least once.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_alert(message: str):
    if not BOT_TOKEN or not CHAT_ID:
        print("[telegram_alert] Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in .env — skipping alert.")
        print("[telegram_alert] Would have sent:", message)
        return False

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    try:
        response = requests.post(url, data={"chat_id": CHAT_ID, "text": message})
        if response.status_code != 200:
            print("[telegram_alert] Failed:", response.text)
            return False
        return True
    except Exception as e:
        print("[telegram_alert] Error:", e)
        return False