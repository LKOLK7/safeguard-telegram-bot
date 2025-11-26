
# Safeguard Telegram Bot (Render-ready, webhook + health check)

A moderation bot for Telegram groups with anti-spam, content filtering, and new member verification.

## Files
- `bot.py` — bot + Starlette server exposing `/webhook`, `/healthz`, and `/`
- `requirements.txt` — minimal deps

## Deploy to Render
1. **Push** this repo to GitHub.
2. In **Render Dashboard** → New → Web Service → connect your repo.
3. **Build Command:** `pip install -r requirements.txt`  
   **Start Command:** `python bot.py`
4. Open the service → **Environment** → add variables:
   - `BOT_TOKEN` — your BotFather token
   - `ADMIN_IDS` — comma-separated IDs (e.g., `12345678,87654321`)
   - `WEBHOOK_SECRET` — any random string (used to validate incoming webhooks)
   > Render injects `PORT` and `RENDER_EXTERNAL_URL` automatically.
5. **Deploy**. On startup, the bot registers the webhook and serves health check endpoints.

## Group setup
- Add the bot as **Admin** with permission to **Restrict Members** (needed for muting).  
- Test with `/start`. Check Render **Logs** if anything fails.
