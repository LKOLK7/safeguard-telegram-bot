
# Safeguard Telegram Bot (Render-ready)

### Features
- Permanent CAPTCHA gate for new members (cannot chat until verified).
- Admin-only commands: `/addbadword`, `/removebadword`, `/togglelinks` (delete + warn + temp-mute).
- Moderation: banned words, link blocking, flood control.
- VirusTotal v3 scans for documents/photos (optional; set `VT_API_KEY`).
- Webhook via Starlette (`/webhook`) + health check (`/healthz`).
- Explicit `allowed_updates` so Telegram delivers join events & requests; drops pending updates.

### Environment Variables (Render Dashboard)
- `BOT_TOKEN` : Telegram bot token from @BotFather  
- `ADMIN_IDS` : Comma-separated **numeric** IDs, e.g. `12345,67890`  
- `WEBHOOK_SECRET` : Optional secret header value (A–Z a–z 0–9 `_` `-`)  
- `VT_API_KEY` : Optional VirusTotal API key  
- `RENDER_EXTERNAL_URL` : Render sets this automatically

### Permissions in Telegram
- Make the bot **Admin** in the group with **Restrict Members** + **Delete Messages**.
- In BotFather: `/setprivacy` → **Disable**, then remove & re‑add the bot to the group.

### Start Command (Render)
