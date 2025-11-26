
#!/usr/bin/env python
# bot.py — Safeguard Telegram Bot (Render-ready, webhook + healthz)
#
# Features:
# - Content moderation (banned words, link blocking)
# - Flood control (rate-limit users; temporary mute)
# - New-member CAPTCHA verification
# - New-member alert (id/is_bot/names/username link/language_code)
# - Admin policy controls (/addbadword, /removebadword, /togglelinks)
# - User commands (/start, /rules, /report, /warnings, /function)
# - Render-compatible webhook server (Starlette) with /webhook & /healthz
#
# NOTES:
# - The bot must be ADMIN in the group with "Restrict Members" rights for muting/restricting.
# - WEBHOOK_SECRET must only use: A–Z a–z 0–9 underscore (_) and hyphen (-).
# - Render injects PORT & RENDER_EXTERNAL_URL automatically.

import os
import re
import random
import logging
from datetime import datetime, timedelta

from telegram import Update, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler,
    CallbackQueryHandler, ChatMemberHandler, filters, AIORateLimiter
)

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

# ----------------------------
# Logging
# ----------------------------
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO
)
logger = logging.getLogger("safeguard-bot")

# ----------------------------
# Environment & Config
# ----------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()}
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "b77604a21c955932fcb178599437aa58")  # must be A-Z a-z 0-9 _ -
BASE_URL = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")  # Render sets this automatically
WEBHOOK_PATH = "/webhook"                                    # endpoint path on our server
WEBHOOK_URL = f"{BASE_URL}{WEBHOOK_PATH}" if BASE_URL else ""  # full HTTPS URL for Telegram

# Safeguard policies (customize as needed)
BAD_WORDS = {"idiot", "stupid", "fool"}   # example list; add your own
BLOCK_LINKS = True
WARN_LIMIT = 2
FLOOD_MAX_MSG = 5
FLOOD_WINDOW_SEC = 10
MUTE_SECONDS = 60  # temporary mute duration

# In-memory state (replace with DB if you need persistence)
PENDING_CAPTCHA = {}           # user_id -> {"chat_id": ..., "answer": ...}
USER_WARNINGS = {}             # (chat_id, user_id) -> count
USER_MSG_TIMES = {}            # (chat_id, user_id) -> [timestamps]

# ----------------------------
# Helpers
# ----------------------------
def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

def contains_link(text: str) -> bool:
    return bool(re.search(r"(https?://|t\.me/|telegram\.me|@[\w_]+)", text, re.IGNORECASE))

async def delete_message_safe(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await context.bot.delete_message(update.effective_chat.id, update.effective_message.message_id)
    except Exception as e:
        logger.debug(f"Delete message failed: {e}")

async def mute_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE, seconds: int = MUTE_SECONDS):
    # Requires bot admin rights with "Restrict Members".
    perms = ChatPermissions(
        can_send_messages=False,
        can_send_media_messages=False,
        can_send_polls=False,
        can_add_web_page_previews=False
    )
    until_date = datetime.now() + timedelta(seconds=seconds)
    await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms, until_date=until_date)

async def unmute_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE):
    perms = ChatPermissions(
        can_send_messages=True,
        can_send_media_messages=True,
        can_send_polls=True,
        can_add_web_page_previews=True
    )
    await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms)

def add_warning(chat_id: int, user_id: int) -> int:
    key = (chat_id, user_id)
    USER_WARNINGS[key] = USER_WARNINGS.get(key, 0) + 1
    return USER_WARNINGS[key]

def record_user_message(chat_id: int, user_id: int) -> int:
    key = (chat_id, user_id)
    now = datetime.now().timestamp()
    times = USER_MSG_TIMES.get(key, [])
    times.append(now)
    USER_MSG_TIMES[key] = [t for t in times if now - t <= FLOOD_WINDOW_SEC]
    return len(USER_MSG_TIMES[key])

def secret_is_valid(token: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_-]{1,256}$", token))

# ----------------------------
# Commands
# ----------------------------
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Hello! I keep this group safe—moderation, anti-spam, and new member verification.\n"
        "Use /rules to see the code of conduct, /function to see all features, or /report to alert admins."
    )

async def cmd_rules(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Group rules:\n"
        "• Be respectful.\n"
        "• No profanity or harassment.\n"
        "• Avoid spam & unsolicited ads.\n"
        "• External links only when relevant.\n"
        "• Follow lecturer’s guidance."
    )

async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    reason = " ".join(context.args) if context.args else "(no reason provided)"
    await update.message.reply_text("Thanks—we have notified the admins.")
    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(
                admin_id,
                f"[REPORT] Chat {update.effective_chat.id} from @{update.effective_user.username or update.effective_user.id}: {reason}"
            )
        except Exception as e:
            logger.debug(f"Notify admin failed: {e}")

async def cmd_warnings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    count = USER_WARNINGS.get((update.effective_chat.id, update.effective_user.id), 0)
    await update.message.reply_text(f"Your current warnings: {count}")

# --- /function: Show bot capabilities ----------------------------------------
async def cmd_function(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🔧 **Safeguard Bot Functions**\n\n"
        "**General (Private & Group)**\n"
        "• /start – Introduction and how to use the bot\n"
        "• /rules – Display the group rules\n"
        "• /report <reason> – Report an issue to admins\n"
        "• /warnings – Show your current warning count\n\n"
        "**Moderation (Group)**\n"
        "• Auto‑filter offensive words (customizable)\n"
        "• Block links (if enabled)\n"
        "• Flood control: mute users who send too many messages too fast\n"
        "• Delete violating messages\n\n"
        "**Verification (Group)**\n"
        "• New members must pass a simple CAPTCHA to chat\n\n"
        "**Admin Controls**\n"
        "• /addbadword <word ...> – Add banned words\n"
        "• /removebadword <word ...> – Remove banned words\n"
        "• /togglelinks – Enable/disable link blocking\n\n"
        "**Notes**\n"
        "• For muting/restricting, the bot must be **admin** with 'Restrict Members' right.\n"
        "• In groups with Privacy Mode ON, only commands are processed unless mentioned."
    )
    await update.message.reply_text(text, parse_mode="Markdown")

# ----------------------------
# Admin policy controls
# ----------------------------
async def addbadword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Usage: /addbadword <word>")
        return
    for w in context.args:
        BAD_WORDS.add(w.lower())
    await update.message.reply_text(f"Added: {', '.join(context.args)}")

async def removebadword(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    if not context.args:
        await update.message.reply_text("Usage: /removebadword <word>")
        return
    removed = []
    for w in context.args:
        wl = w.lower()
        if wl in BAD_WORDS:
            BAD_WORDS.remove(wl)
            removed.append(w)
    await update.message.reply_text(f"Removed: {', '.join(removed) if removed else '(none)'}")

async def togglelinks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    global BLOCK_LINKS
    BLOCK_LINKS = not BLOCK_LINKS
    await update.message.reply_text(f"Link blocking is now {'ON' if BLOCK_LINKS else 'OFF'}.")

# ----------------------------
# Moderation handler
# ----------------------------
async def moderate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    user = msg.from_user
    chat_id = update.effective_chat.id
    text = (msg.text or msg.caption or "")

    if is_admin(user.id):
        return

    # Flood control
    count = record_user_message(chat_id, user.id)
    if count > FLOOD_MAX_MSG:
        await delete_message_safe(update, context)
        await msg.reply_text(f"⌛ Slow down, @{user.username or user.first_name} (muted {MUTE_SECONDS}s).")
        await mute_user(chat_id, user.id, context, seconds=MUTE_SECONDS)
        return

    # Banned words
    if any(bad in text.lower() for bad in BAD_WORDS):
        await delete_message_safe(update, context)
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await msg.reply_text(f"🚫 Keep it civil. Muted for {MUTE_SECONDS}s.")
            await mute_user(chat_id, user.id, context, seconds=MUTE_SECONDS)
        else:
            await msg.reply_text(f"⚠️ Warning ({total}/{WARN_LIMIT}). Avoid offensive language.")
        return

    # Links
    if BLOCK_LINKS and contains_link(text):
        await delete_message_safe(update, context)
        await msg.reply_text("🔗 Links are not allowed here. If it’s class-related, ask an admin.")
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await mute_user(chat_id, user.id, context, seconds=MUTE_SECONDS)

# ----------------------------
# New member verification + alert (CAPTCHA + details)
# ----------------------------
async def welcome_verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    for new_member in update.message.new_chat_members:
        # 1) Restrict new member initially (CAPTCHA gate)
        await mute_user(chat_id, new_member.id, context, seconds=MUTE_SECONDS)

        # 2) Build a verification challenge
        correct = random.randint(1, 4)
        options = list(range(1, 5))
        random.shuffle(options)
        keyboard = [
            [InlineKeyboardButton(str(n), callback_data=f"verify:{new_member.id}:{int(n==correct)}")]
            for n in options
        ]
        PENDING_CAPTCHA[new_member.id] = {"chat_id": chat_id, "answer": correct}

        # 3) Send the verification prompt
        await context.bot.send_message(
            chat_id,
            f"👋 Welcome, @{new_member.username or new_member.first_name}!\n"
            f"Please verify: pick **{correct}** to unlock chatting.",
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown"
        )

        # 4) Compose the alert with user details (exact format requested)
        uid = new_member.id
        is_bot = "true" if new_member.is_bot else "false"
        first_name = new_member.first_name or "-"
        last_name = new_member.last_name or "-"
        uname = new_member.username or "-"
        ulink = f"(https://t.me/{new_member.username})" if new_member.username else "(-)"
        lang = getattr(new_member, "language_code", None) or "-"
        lang_link = "(-)"  # keep same placeholder style

        alert_text = (
            f"id: {uid}\n"
            f" ├ is_bot: {is_bot}\n"
            f" ├ first_name: {first_name}\n"
            f" ├ last_name: {last_name}\n"
            f" ├ username: {uname} {ulink}\n"
            f" └ language_code: {lang} {lang_link}"
        )

        # 5) Post the alert to the group
        await context.bot.send_message(chat_id, alert_text)

        # 6) (Optional) Notify admins privately as well
        for admin_id in ADMIN_IDS:
            try:
                await context.bot.send_message(admin_id, f"[NEW MEMBER]\n{alert_text}")
            except Exception:
                pass

# ----------------------------
# Verify button callback
# ----------------------------
async def verify_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    try:
        _, uid_str, ok_str = query.data.split(":")
        user_id = int(uid_str)
        is_ok = bool(int(ok_str))
        if query.from_user.id != user_id:
            await query.edit_message_text("This verification is not for you.")
            return
        pending = PENDING_CAPTCHA.get(user_id)
        if not pending:
            await query.edit_message_text("No active verification.")
            return
        chat_id = pending["chat_id"]
        if is_ok:
            await unmute_user(chat_id, user_id, context)
            await query.edit_message_text("✅ Verified. Welcome!")
            PENDING_CAPTCHA.pop(user_id, None)
        else:
            await query.edit_message_text("❌ Wrong answer. Try again.")
    except Exception as e:
        logger.debug(f"verify_callback error: {e}")

# ----------------------------
# Build PTB Application (async + rate limiter)
# ----------------------------
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing. Set it in environment.")

application = (
    ApplicationBuilder()
    .token(BOT_TOKEN)
    .rate_limiter(AIORateLimiter())  # avoid Telegram API flood limits
    .build()
)

# Register handlers
application.add_handler(CommandHandler("start", cmd_start))
application.add_handler(CommandHandler("rules", cmd_rules))
application.add_handler(CommandHandler("report", cmd_report))
application.add_handler(CommandHandler("warnings", cmd_warnings))
application.add_handler(CommandHandler("function", cmd_function))

application.add_handler(CommandHandler("addbadword", addbadword))
application.add_handler(CommandHandler("removebadword", removebadword))
application.add_handler(CommandHandler("togglelinks", togglelinks))

application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, moderate))
application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, welcome_verify))
application.add_handler(CallbackQueryHandler(verify_callback, pattern=r"^verify:"))
application.add_handler(ChatMemberHandler(lambda *_: None))  # optional

# Optional: set Telegram command menu
async def set_my_commands():
    try:
        await application.bot.set_my_commands([
            ("start", "Introduction"),
            ("rules", "Show group rules"),
            ("report", "Report an issue to admins"),
            ("warnings", "Show your warnings"),
            ("function", "Show all bot functions"),
        ])
    except Exception as e:
        logger.debug(f"set_my_commands failed: {e}")

# ----------------------------
# Starlette Web App (webhook + health check)
# ----------------------------
async def healthz(request: Request):
    return JSONResponse({"status": "ok"})

async def root(request: Request):
    return PlainTextResponse("OK", status_code=200)

async def webhook(request: Request):
    # Verify secret token header from Telegram when set_webhook(..., secret_token=WEBHOOK_SECRET)
    if secret_is_valid(WEBHOOK_SECRET):
        hdr = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if hdr != WEBHOOK_SECRET:
            logger.warning("Forbidden webhook call: secret mismatch")
            return PlainTextResponse("forbidden", status_code=403)

    try:
        data = await request.json()
    except Exception:
        return PlainTextResponse("bad request", status_code=400)

    update = Update.de_json(data, application.bot)
    await application.process_update(update)
    return PlainTextResponse("ok")

routes = [
    Route("/", root, methods=["GET"]),
    Route("/healthz", healthz, methods=["GET"]),
    Route(WEBHOOK_PATH, webhook, methods=["POST"]),  # /webhook
]
app = Starlette(routes=routes)

# Startup/Shutdown: PTB lifecycle + webhook registration
@app.on_event("startup")
async def on_startup():
    logger.info("Application starting …")
    await application.initialize()
    await application.start()

    # Register webhook with secret if valid; otherwise without (to avoid Telegram BadRequest)
    try:
        if WEBHOOK_URL:
            if secret_is_valid(WEBHOOK_SECRET):
                await application.bot.set_webhook(url=WEBHOOK_URL, secret_token=WEBHOOK_SECRET)
                logger.info(f"Webhook set to {WEBHOOK_URL} with secret.")
            else:
                logger.warning("WEBHOOK_SECRET invalid; setting webhook without secret.")
                await application.bot.set_webhook(url=WEBHOOK_URL)
                logger.info(f"Webhook set to {WEBHOOK_URL} (no secret).")
    except Exception as e:
        logger.error(f"set_webhook failed: {e}")
        # Exit early so Render restarts the service and logs the error clearly
        raise

    await set_my_commands()
    logger.info("Application started.")

@app.on_event("shutdown")
async def on_shutdown():
    logger.info("Application stopping …")
    await application.stop()
    logger.info("Application stopped.")

# ----------------------------
# Main (Render: uses PORT env var)
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "10000"))  # Render sets PORT automatically
    uvicorn.run("bot:app", host="0.0.0.0", port=port, workers=1)
