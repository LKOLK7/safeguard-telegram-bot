
# Safeguard Telegram Bot (Render‑ready, 3 files)

A lightweight moderation bot for Telegram groups: content filtering, anti‑spam, and new‑member verification.
This repo contains only **three files**: `bot.py`, `requirements.txt`, `README.md`.

## Features
- Banned words & link blocking
- Flood control & temporary mute (requires bot admin rights)
- CAPTCHA‑based new member verification (inline buttons)
- Admin policy commands: `/addbadword`, `/removebadword`, `/togglelinks`, `/warnings`

## Environment Variables (set in Render)
- `BOT_TOKEN` — Telegram bot token from **@BotFather**
- `ADMIN_IDS` — comma‑separated Telegram user IDs (admins who can change policies)
- `WEBHOOK_SECRET` — any random string (used to verify webhook requests)

## Deploy on Render (Web Service)
1. Push this repo to GitHub (or use existing repo).
2. In **Render.com** → **New → Web Service** → select your repo.
3. **Build Command:** `pip install -r requirements.txt`
4. **Start Command:** `python bot.py`
5. Go to **Environment** and add:
   - `BOT_TOKEN`
   - `ADMIN_IDS` (e.g., `12345678,87654321`)
   - `WEBHOOK_SECRET` (e.g., `verify-2025`)
6. Deploy. Render sets `PORT` and `RENDER_EXTERNAL_URL` automatically. On startup, the bot registers its webhook at `https://<your-service>.onrender.com/webhook`.
7. In Telegram, **add the bot to your group** and make it **admin** with “Restrict Members” permission (needed for muting).

### Health Check
- Render pings `/healthz` (returns `200 OK`). The root `/` also returns `200 OK`.
- Webhook endpoint: `POST /webhook` (secured by `WEBHOOK_SECRET` header `X-Telegram-Bot-Api-Secret-Token`).

## Local testing (optional)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export BOT_TOKEN=... ADMIN_IDS=11111111 WEBHOOK_SECRET=change-me
export PORT=8000 RENDER_EXTERNAL_URL=http://localhost:8000  # for local tests
python bot.py
