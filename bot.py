
#!/usr/bin/env python
"""
Safeguard Telegram Bot (Render-ready, PTB v20, Starlette webhook) + VirusTotal scanner

Design:
- python-telegram-bot v20 ApplicationBuilder with .updater(None) for a custom Starlette webhook
- Startup does NOT raise on set_webhook failure (avoids "Application exited early" on Render)
- Group diagnostics: error handler + logs in /start + a group command tap to inspect command routing

Env vars:
  BOT_TOKEN, ADMIN_IDS, WEBHOOK_SECRET (optional), VT_API_KEY (optional),
  RENDER_EXTERNAL_URL (auto, used to build WEBHOOK_URL)

Routes:
  GET  /          -> "OK"
  GET  /healthz   -> {"status":"ok"}
  POST /webhook   -> receives Telegram Update JSON (with optional secret header)
"""

import os
import re
import sys
import random
import logging
import asyncio
from datetime import datetime, timedelta

# Optional dependency guard for VirusTotal
try:
    import requests
except ImportError:
    requests = None

from telegram import (
    Update, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
)
from telegram.helpers import escape_markdown
import telegram  # version logging

# Starlette web server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

# ----------------- Logging -----------------
logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s %(message)s", level=logging.INFO)
logger = logging.getLogger("safeguard-bot")

# ----------------- Environment -----------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()}
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "change-me")  # allowed: A-Z a-z 0-9 _ -
BASE_URL = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
WEBHOOK_PATH = "/webhook"
WEBHOOK_URL = f"{BASE_URL}{WEBHOOK_PATH}" if BASE_URL else ""
VT_API_KEY = os.getenv("VT_API_KEY", "")

# VirusTotal (v3)
VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSES_URL_TPL = "https://www.virustotal.com/api/v3/analyses/{}"
VT_HEADERS = {"x-apikey": VT_API_KEY}

# Policies
BAD_WORDS = {"idiot", "stupid", "fool"}
BLOCK_LINKS = True
WARN_LIMIT = 2
FLOOD_MAX_MSG = 5
FLOOD_WINDOW_SEC = 10
MUTE_SECONDS = 60

# State
PENDING_CAPTCHA = {}   # user_id -> {"chat_id": ..., "answer": ...}
USER_WARNINGS = {}     # (chat_id, user_id) -> count
USER_MSG_TIMES = {}    # (chat_id, user_id) -> [timestamps]
UNVERIFIED = set()     # {(chat_id, user_id)} under CAPTCHA gate

ENGINES_FOR_PROGRESS = [
    "Kaspersky", "Avast", "BitDefender", "ESET-NOD32", "Microsoft", "Sophos", "TrendMicro",
    "McAfee", "DrWeb", "Fortinet", "ClamAV", "Paloalto", "Malwarebytes", "VIPRE"
]

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

URL_REGEX = re.compile(r"(https?://\S+|www\.\S+|t\.me/\S+|telegram\.me/\S+|@\w+)", re.IGNORECASE)
def contains_link(text: str) -> bool:
    return bool(URL_REGEX.search(text or ""))

def delete_message_safe(update: Update, context):
    try:
        return context.bot.delete_message(update.effective_chat.id, update.effective_message.message_id)
    except Exception as e:
        logger.debug(f"Delete message failed: {e}")

async def restrict_user(chat_id: int, user_id: int, context, until_date=None):
    perms = ChatPermissions(
        can_send_messages=False,
        can_send_media_messages=False,
        can_send_polls=False,
        can_add_web_page_previews=False
    )
    try:
        await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms, until_date=until_date)
    except Exception as e:
        logger.warning(f"Restrict failed (missing rights?): {e}")

async def unrestrict_user(chat_id: int, user_id: int, context):
    perms = ChatPermissions(
        can_send_messages=True,
        can_send_media_messages=True,
        can_send_polls=True,
        can_add_web_page_previews=True
    )
    try:
        await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms)
    except Exception as e:
        logger.warning(f"Unrestrict failed: {e}")

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
    return bool(re.match(r'^[A-Za-z0-9_\-]{1,256}$', token))

# ----------------- Diagnostics -----------------
async def log_all_updates(update: Update, context):
    types = []
    if update.message: types.append("message")
    if update.edited_message: types.append("edited_message")
    if update.channel_post: types.append("channel_post")
    if update.edited_channel_post: types.append("edited_channel_post")
    if update.inline_query: types.append("inline_query")
    if update.chosen_inline_result: types.append("chosen_inline_result")
    if update.callback_query: types.append("callback_query")
    if update.shipping_query: types.append("shipping_query")
    if update.pre_checkout_query: types.append("pre_checkout_query")
    if update.poll: types.append("poll")
    if update.poll_answer: types.append("poll_answer")
    if update.my_chat_member: types.append("my_chat_member")
    if update.chat_member: types.append("chat_member")
    if update.chat_join_request: types.append("chat_join_request")
    logger.info(f"UPDATE TYPES: {types}")

# ----------------- Commands -----------------
async def cmd_start(update: Update, context):
    # Helpful group diagnostics
    logger.info(
        f"/start in chat_id={update.effective_chat.id}, type={update.effective_chat.type}, "
        f"is_topic_message={getattr(update.message, 'is_topic_message', False)}, "
        f"user_id={update.effective_user.id}"
    )
    try:
        await update.message.reply_text(
            "Hello! I keep this group safe—moderation, anti-spam, and new member verification.\n"
            "Use /rules to see the code of conduct, /function to see all features, or /report to alert admins.\n\n"
            "You can also send a file or photo and I’ll **scan it with VirusTotal** to check for malware."
        )
    except Exception as e:
        # If the bot lacks permission to send in this chat/topic, log the error clearly
        logger.error(f"/start reply failed in chat {update.effective_chat.id}: {e}")

async def cmd_rules(update: Update, context):
    await update.message.reply_text(
        "Group rules:\n"
        "• Be respectful.\n"
        "• No profanity or harassment.\n"
        "• Avoid spam & unsolicited ads.\n"
        "• External links only when relevant.\n"
        "• Follow lecturer’s guidance."
    )

async def cmd_report(update: Update, context):
    reason = " ".join(context.args) if getattr(context, "args", None) else "(no reason provided)"
    await update.message.reply_text("Thanks—we have notified the admins.")
    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(
                admin_id,
                f"[REPORT] Chat {update.effective_chat.id} from @{update.effective_user.username or update.effective_user.id}: {reason}"
            )
        except Exception as e:
            logger.debug(f"Notify admin failed: {e}")

async def cmd_warnings(update: Update, context):
    count = USER_WARNINGS.get((update.effective_chat.id, update.effective_user.id), 0)
    await update.message.reply_text(f"Your current warnings: {count}")

# Quick connectivity test
async def cmd_ping(update: Update, context):
    try:
        await update.message.reply_text("🏓 pong")
    except Exception as e:
        logger.error(f"/ping reply failed in chat {update.effective_chat.id}: {e}")

async def cmd_function(update: Update, context):
    text = (
        "🛠 **Safeguard Bot Functions**\n\n"
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
        "• New members must pass a simple CAPTCHA to chat (permanent gate until verified)\n"
        "• Instant alert with user details when someone joins (UID shown)\n\n"
        "**Admin Controls**\n"
        "• /addbadword <word ...> – Add banned words (admins only)\n"
        "• /removebadword <word ...> – Remove banned words (admins only)\n"
        "• /togglelinks – Enable/disable link blocking (admins only)\n\n"
        "**Security Scanner**\n"
        "• Send a **file** or **photo** to automatically scan with **VirusTotal** and get a readable summary.\n"
        "  (Public API has rate limits; use wisely.)\n\n"
        "**Notes**\n"
        "• The bot must be **admin** with 'Restrict Members' + 'Delete Messages'.\n"
        "• Disable Group Privacy in BotFather so the bot can receive normal group messages."
    )
    await update.message.reply_text(text, parse_mode="Markdown")

# ----------------- Admin policy controls -----------------
async def enforce_admin_violation(update: Update, context, action_label: str = "change bot settings"):
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    msg = update.effective_message
    delete_message_safe(update, context)
    total = add_warning(chat_id, user_id)
    if total >= WARN_LIMIT:
        try:
            await msg.reply_text(f"🚫 You are not allowed to {action_label}. Muted for {MUTE_SECONDS}s.")
        except Exception:
            pass
        await restrict_user(chat_id, user_id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
    else:
        try:
            await msg.reply_text(
                f"⚠️ You are not allowed to {action_label}. Warning ({total}/{WARN_LIMIT}).\n"
                f"Further violations may result in a temporary mute."
            )
        except Exception:
            pass

async def addbadword(update: Update, context):
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await enforce_admin_violation(update, context, action_label="change bot settings (/addbadword)")
        return
    msg = update.effective_message
    if not getattr(context, "args", None):
        await msg.reply_text("Usage: /addbadword <word>")
        return
    for w in context.args:
        BAD_WORDS.add(w.lower())
    await msg.reply_text(f"Added: {', '.join(context.args)}")

async def removebadword(update: Update, context):
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await enforce_admin_violation(update, context, action_label="change bot settings (/removebadword)")
        return
    msg = update.effective_message
    if not getattr(context, "args", None):
        await msg.reply_text("Usage: /removebadword <word>")
        return
    removed = []
    for w in context.args:
        wl = w.lower()
        if wl in BAD_WORDS:
            BAD_WORDS.remove(wl)
            removed.append(w)
    await msg.reply_text(f"Removed: {', '.join(removed) if removed else '(none)'}")

async def togglelinks(update: Update, context):
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await enforce_admin_violation(update, context, action_label="change bot settings (/togglelinks)")
        return
    global BLOCK_LINKS
    BLOCK_LINKS = not BLOCK_LINKS
    await update.effective_message.reply_text(f"Link blocking is now {'ON' if BLOCK_LINKS else 'OFF'}.")

# ----------------- Gate for unverified -----------------
async def gate_unverified(update: Update, context):
    chat = update.effective_chat
    user = update.effective_user
    msg = update.effective_message
    is_start_cmd = bool(msg and msg.text and msg.text.strip().startswith("/start"))
    if chat.type in ("group", "supergroup") and (chat.id, user.id) in UNVERIFIED and not is_start_cmd:
        delete_message_safe(update, context)
        try:
            await context.bot.send_message(chat.id, f"⛔ @{user.username or user.first_name}, please complete the CAPTCHA above to start chatting.")
        except Exception:
            pass

# ----------------- Moderation -----------------
async def moderate(update: Update, context):
    msg = update.effective_message
    user = msg.from_user
    chat_id = update.effective_chat.id
    text = (msg.text or msg.caption or "")
    if is_admin(user.id):
        return

    count = record_user_message(chat_id, user.id)
    if count > FLOOD_MAX_MSG:
        delete_message_safe(update, context)
        await msg.reply_text(f"⌛ Slow down, @{user.username or user.first_name} (muted {MUTE_SECONDS}s).")
        await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
        return

    if any(bad in text.lower() for bad in BAD_WORDS):
        delete_message_safe(update, context)
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await msg.reply_text(f"🚫 Keep it civil. Muted for {MUTE_SECONDS}s.")
            await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
        else:
            await msg.reply_text(f"⚠️ Warning ({total}/{WARN_LIMIT}). Avoid offensive language.")
        return

    if BLOCK_LINKS and contains_link(text):
        delete_message_safe(update, context)
        await msg.reply_text("🔗 Links are not allowed here. If it’s class-related, ask an admin.")
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))

# ----------------- Verification -----------------
async def welcome_verify(update: Update, context):
    chat_id = update.effective_chat.id
    for new_member in update.message.new_chat_members:
        UNVERIFIED.add((chat_id, new_member.id))
        await restrict_user(chat_id, new_member.id, context, until_date=None)

        correct = random.randint(1, 4)
        options = list(range(1, 5))
        random.shuffle(options)
        keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify:{new_member.id}:{int(n==correct)}")] for n in options]
        PENDING_CAPTCHA[new_member.id] = {"chat_id": chat_id, "answer": correct}
        await context.bot.send_message(
            chat_id,
            (f"👋 Welcome, @{new_member.username or new_member.first_name}!\n"
             f"Please verify: pick **{correct}** to unlock chatting.\n"
             f"UID: `{new_member.id}`"),
            reply_markup=InlineKeyboardMarkup(keyboard),
            parse_mode="Markdown"
        )

        uid = new_member.id
        is_bot = "true" if new_member.is_bot else "false"
        first_name = new_member.first_name or "-"
        last_name = new_member.last_name or "-"
        uname = new_member.username or "-"
        ulink = f"(https://t.me/{new_member.username})" if new_member.username else "(-)"
        lang = getattr(new_member, "language_code", None) or "-"
        alert_text = (
            "📣 NEW MEMBER ALERT\n"
            f"• UID: {uid}\n"
            f"• is_bot: {is_bot}\n"
            f"• first_name: {first_name}\n"
            f"• last_name: {last_name}\n"
            f"• username: {uname} {ulink}\n"
            f"• language_code: {lang}"
        )
        await context.bot.send_message(chat_id, alert_text)

async def handle_join_request(update: Update, context):
    req = update.chat_join_request
    chat_id = req.chat.id
    user_id = req.from_user.id
    UNVERIFIED.add((chat_id, user_id))
    logger.info(f"JOIN REQUEST: marked UNVERIFIED {(chat_id, user_id)}")

# ----------------- VirusTotal scanning -----------------
async def vt_scan_and_report(file_path: str, progress_msg):
    if requests is None:
        await progress_msg.edit_text(
            "❌ The 'requests' library is not installed. Add it to requirements.txt and redeploy."
        )
        return

    if not VT_API_KEY:
        await progress_msg.edit_text("❌ VirusTotal API key is not configured (VT_API_KEY).")
        return

    try:
        with open(file_path, "rb") as f:
            resp = requests.post(VT_FILE_SCAN_URL, headers=VT_HEADERS, files={"file": f})
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id")
            if not analysis_id:
                await progress_msg.edit_text("❌ Failed to get analysis ID from VirusTotal.")
                return
        await progress_msg.edit_text("✅ File uploaded! Scanning in progress...")
    except Exception as e:
        await progress_msg.edit_text(f"❌ Error uploading file: {escape_markdown(str(e), version=2)}", parse_mode="MarkdownV2")
        return

    engine_index = 0
    previous_text = None
    attempts = 0
    max_attempts = 120
    while attempts < max_attempts:
        await asyncio.sleep(5)
        try:
            status_resp = requests.get(VT_ANALYSES_URL_TPL.format(analysis_id), headers=VT_HEADERS)
            status_resp.raise_for_status()
            attrs = status_resp.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                results = attrs.get("results", {})
                malicious, suspicious, clean = [], [], []
                for engine, det in results.items():
                    category = det.get("category")
                    result_text = det.get("result")
                    if category == "malicious":
                        malicious.append(f"• {engine}: {result_text}")
                    elif category == "suspicious":
                        suspicious.append(f"• {engine}: {result_text or 'Suspicious'}")
                    else:
                        clean.append(f"• {engine}: clean")

                grouped = "──────────────\n"
                if malicious:
                    grouped += "🔴 *Malicious:*\n" + "\n".join(malicious) + "\n\n"
                if suspicious:
                    grouped += "🟠 *Suspicious:*\n" + "\n".join(suspicious) + "\n\n"
                if clean:
                    grouped += "✅ *Clean:*\n" + "\n".join(clean) + "\n"
                grouped += "──────────────"

                summary = (
                    f"✅ **Scan Complete!**\n\n"
                    f"🔎 **Summary:**\n"
                    f"• 🛡 *Malicious:* `{stats.get('malicious', 0)}`\n"
                    f"• ⚠️ *Suspicious:* `{stats.get('suspicious', 0)}`\n"
                    f"• ✅ *Harmless:* `{stats.get('harmless', 0)}`\n"
                    f"• ❓ *Undetected:* `{stats.get('undetected', 0)}`\n\n"
                    f"🧠 **Detected details:**\n{grouped}\n\n"
                    f"Powered by VirusTotal API v3"
                )
                await progress_msg.edit_text(escape_markdown(summary, version=2), parse_mode="MarkdownV2")
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.error(f"Error deleting file: {e}")
                return

            new_banner = f"🔎 Scanning... please wait ({ENGINES_FOR_PROGRESS[engine_index]})"
            if new_banner != previous_text:
                await progress_msg.edit_text(new_banner)
                previous_text = new_banner
            engine_index = (engine_index + 1) % len(ENGINES_FOR_PROGRESS)
            attempts += 1
        except Exception as e:
            logger.error(f"Error fetching VT report: {e}")
            attempts += 1

    await progress_msg.edit_text("⚠️ Scan taking too long. Please check manually on VirusTotal.")
    try:
        os.remove(file_path)
    except Exception as e:
        logger.error(f"Error deleting file after timeout: {e}")

async def scan_document(update: Update, context):
    doc = update.message.document
    file = await doc.get_file()
    file_path = await file.download_to_drive()
    progress_msg = await update.message.reply_text("⏳ Uploading file to VirusTotal and starting scan...")
    await vt_scan_and_report(file_path, progress_msg)

async def scan_photo(update: Update, context):
    photo = update.message.photo[-1]
    file = await photo.get_file()
    file_path = await file.download_to_drive()
    progress_msg = await update.message.reply_text("⏳ Uploading image to VirusTotal and starting scan...")
    await vt_scan_and_report(file_path, progress_msg)

# ----------------- Verify button -----------------
async def verify_callback(update: Update, context):
    query = update.callback_query
    await query.answer()
    try:
        _, uid_str, ok_str = query.data.split(":")
        user_id = int(uid_str)
        is_ok = bool(int(ok_str))
        pending = PENDING_CAPTCHA.get(user_id)
        if not pending:
            await query.edit_message_text("No active verification.")
            return
        chat_id = pending["chat_id"]
        if query.from_user.id != user_id:
            await query.edit_message_text("This verification is not for you.")
            return
        if is_ok:
            await unrestrict_user(chat_id, user_id, context)
            UNVERIFIED.discard((chat_id, user_id))
            await query.edit_message_text("✅ Verified. Welcome!")
            PENDING_CAPTCHA.pop(user_id, None)
        else:
            await query.edit_message_text("❌ Wrong answer. Try again.")
    except Exception as e:
        logger.debug(f"verify_callback error: {e}")

# ----------------- PTB v20 Application (custom webhook; no Updater) -----------------
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing. Set it in environment.")

from telegram.ext import (
    ApplicationBuilder, MessageHandler, CommandHandler, CallbackQueryHandler,
    ChatMemberHandler, ChatJoinRequestHandler, filters, AIORateLimiter
)

# Version & URL diagnostics
logger.info(f"Python: {sys.version}")
logger.info(f"python-telegram-bot: {telegram.__version__}")
logger.info(f"RENDER_EXTERNAL_URL: {os.getenv('RENDER_EXTERNAL_URL')}")
logger.info(f"WEBHOOK_URL: {WEBHOOK_URL or '(empty)'}")

builder = ApplicationBuilder().token(BOT_TOKEN).updater(None)  # custom webhook (PTB example)
try:
    builder = builder.rate_limiter(AIORateLimiter())  # optional extra installed via requirements
except Exception as e:
    logger.warning(f"AIORateLimiter unavailable ({e}); starting without rate limiter.")

application = builder.build()
bot_for_update = application.bot

# Log exact bot username on startup
BOT_USERNAME = None

# Global error handler so we see permission problems in group replies
async def on_error(update: object, context):
    logger.error("Handler error", exc_info=context.error)
application.add_error_handler(on_error)

# Diagnostics
application.add_handler(MessageHandler(filters.ALL, log_all_updates), group=-1)

# Gate first
group_chats_filter_v20 = (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP)
application.add_handler(MessageHandler(group_chats_filter_v20 & filters.ALL, gate_unverified), group=0)

# Commands
application.add_handler(CommandHandler("start", cmd_start))
application.add_handler(CommandHandler("rules", cmd_rules))
application.add_handler(CommandHandler("report", cmd_report))
application.add_handler(CommandHandler("warnings", cmd_warnings))
application.add_handler(CommandHandler("function", cmd_function))
application.add_handler(CommandHandler("ping", cmd_ping))
application.add_handler(CommandHandler("addbadword", addbadword))
application.add_handler(CommandHandler("removebadword", removebadword))
application.add_handler(CommandHandler("togglelinks", togglelinks))

# --- Group command tap (logs raw command text & entities for troubleshooting) ---
async def group_command_tap(update: Update, context):
    msg = update.message
    txt = msg.text or ""
    ents = getattr(msg, "entities", None)
    logger.info(f"GROUP COMMAND SEEN: text={txt!r}, entities={ents!r}, chat_id={update.effective_chat.id}")
application.add_handler(MessageHandler(filters.COMMAND & group_chats_filter_v20, group_command_tap), group=1)

# Moderation / join / scanners
application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, moderate))
application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, welcome_verify))
application.add_handler(ChatJoinRequestHandler(handle_join_request))
application.add_handler(MessageHandler(group_chats_filter_v20 & filters.Document.ALL, scan_document))
application.add_handler(MessageHandler(group_chats_filter_v20 & filters.PHOTO, scan_photo))
application.add_handler(CallbackQueryHandler(verify_callback, pattern=r"^verify:"))
application.add_handler(ChatMemberHandler(lambda *_: None))

# ----------------- Commands menu -----------------
async def set_my_commands():
    try:
        cmds = [
            BotCommand("start", "Introduction"),
            BotCommand("rules", "Show group rules"),
            BotCommand("report", "Report an issue to admins"),
            BotCommand("warnings", "Show your warnings"),
            BotCommand("function", "Show all bot functions"),
            BotCommand("ping", "Quick connectivity test"),
        ]
        await application.bot.set_my_commands(cmds)
    except Exception as e:
        logger.debug(f"set_my_commands failed: {e}")

# ----------------- Starlette Web App -----------------
async def healthz(request: Request):
    return JSONResponse({"status": "ok"})

async def root(request: Request):
    return PlainTextResponse("OK", status_code=200)

async def webhook(request: Request) -> Response:
    # Optional secret header check
    if secret_is_valid(WEBHOOK_SECRET):
        hdr = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if hdr != WEBHOOK_SECRET:
            logger.warning("Forbidden webhook call: secret mismatch")
            return PlainTextResponse("forbidden", status_code=403)
    try:
        data = await request.json()
    except Exception:
        return PlainTextResponse("bad request", status_code=400)

    # Feed the update into PTB (custom webhook pattern)
    await application.update_queue.put(Update.de_json(data=data, bot=bot_for_update))
    return Response()

routes = [
    Route("/", root, methods=["GET"]),
    Route("/healthz", healthz, methods=["GET"]),
    Route(WEBHOOK_PATH, webhook, methods=["POST"]),
]
app = Starlette(routes=routes)

# ----------------- Startup/Shutdown -----------------
@app.on_event("startup")
async def on_startup():
    logger.info(f"Application starting … WEBHOOK_URL={WEBHOOK_URL!r} secret_valid={secret_is_valid(WEBHOOK_SECRET)}")

    # Resolve exact bot username for addressing in groups
    try:
        me = await application.bot.get_me()
        BOT_USERNAME = me.username
        logger.info(f"Bot identity: id={me.id}, username=@{BOT_USERNAME}")
    except Exception as e:
        logger.warning(f"get_me failed: {e}")

    await application.initialize()
    await application.start()

    # Register webhook (avoid crashing if it fails)
    allowed = Update.ALL_TYPES
    try:
        if WEBHOOK_URL:
            if secret_is_valid(WEBHOOK_SECRET):
                await bot_for_update.set_webhook(
                    url=WEBHOOK_URL,
                    secret_token=WEBHOOK_SECRET,
                    allowed_updates=allowed,
                    drop_pending_updates=True,
                )
                logger.info(f"Webhook set to {WEBHOOK_URL} with secret; allowed_updates={allowed}")
            else:
                await bot_for_update.set_webhook(
                    url=WEBHOOK_URL,
                    allowed_updates=allowed,
                    drop_pending_updates=True,
                )
                logger.info(f"Webhook set to {WEBHOOK_URL} (no secret); allowed_updates={allowed}")
        else:
            logger.warning("WEBHOOK_URL is empty; skipping set_webhook.")
    except Exception as e:
        logger.error(f"set_webhook failed: {e}")
        # Keep serving so health checks pass and you can fix webhook later

    await set_my_commands()
    logger.info("Application started.")

@app.on_event("shutdown")
async def on_shutdown():
    logger.info("Application stopping …")
    try:
        await application.stop()
    except Exception as e:
        logger.warning(f"Error stopping application: {e}")
    logger.info("Application stopped.")

# ----------------- Main (Render: python bot.py) -----------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "10000"))
    uvicorn.run("bot:app", host="0.0.0.0", port=port, workers=1)
