
# Safeguard Telegram Bot (Render-ready)

Features:
- Permanent CAPTCHA gate for new members (cannot chat until verified).
- Admin-only enforcement: `/addbadword`, `/removebadword`, `/togglelinks`.
- Moderation: banned words, link blocking, flood control.
- VirusTotal v3 scan for documents/photos (optional; set `VT_API_KEY`).
- Starlette webhook (`/webhook`) + health check (`/healthz`).

## Environment Variables (Render Dashboard)
- `BOT_TOKEN`         : Your bot token from @BotFather
- `ADMIN_IDS`         : Comma-separated numeric IDs (e.g., `12345,67890`)
- `WEBHOOK_SECRET`    : Optional token (A–Z a–z 0–9 `_` `-`)
- `VT_API_KEY`        : Optional VirusTotal API key
- `RENDER_EXTERNAL_URL`: Render sets this automatically

## Permissions in Telegram
- Add the bot to your group as **Admin** with:
  - **Restrict Members**
  - **Delete Messages**
- In BotFather: `/setprivacy` → **Disable**.
  Then remove & re-add the bot to your group.

## Start Command (Render)
