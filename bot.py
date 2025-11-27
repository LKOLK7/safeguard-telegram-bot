
#!/usr/bin/env python
"""
Safeguard Telegram Bot (Render-ready, PTB v20, Starlette webhook) + VirusTotal scanner

- PTB v20 custom webhook (.updater(None)) with Starlette.
- Global Defaults(block=False) so multiple handlers can run per update.
- Deletion is async + awaited everywhere.
- Scan documents & photos in BOTH group and DM (filters.Document.ALL & filters.PHOTO).
- New member alert (details posted to the group) on NEW_CHAT_MEMBERS.
- Robust startup: log PORT, run uvicorn with app object, never crash on set_webhook failures.
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

# Links/mentions
URL_REGEX = re.compile(r"(https?://\S+|www\.\S+|t\.me/\S+|telegram\.me/\S+|@\w+)", re.IGNORECASE)
def contains_link(text: str) -> bool:
    return bool(URL_REGEX.search(text or ""))

# --- Deletion MUST be awaited ---
async def delete_message_safe(update: Update, context):
    try:
        await context.bot.delete_message(update.effective_chat.id, update.effective_message.message_id)
        logger.info(f"Deleted offending message {update.effective_message.message_id} in chat {update.effective_chat.id}")
    except Exception as e:
        logger.warning(f"Delete message failed in chat {update.effective_chat.id}: {e}")

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
    logger.info(f"[HANDLER] /start fired in chat_id={update.effective_chat.id}")
    try:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=("Hello! I keep this group safe—moderation, anti-spam, and new member verification.\n"
                  "Use /rules to see the code of conduct, /function to see all features, or /report to alert admins.\n\n"
                  "You can also send a file or photo and I’ll **scan it with VirusTotal** to check for malware.")
        )
    except Exception as e:
        logger.error(f"/start send_message failed in chat {update.effective_chat.id}: {e}")

async def cmd_rules(update: Update, context):
    await context.bot.send_message(update.effective_chat.id, "Group rules:\n"
                               "• Be respectful.\n"
                               "• No profanity or harassment.\n"
                               "• Avoid spam & unsolicited ads.\n"
                               "• External links only when relevant.\n"
                               "• Follow lecturer’s guidance.")

async def cmd_report(update: Update, context):
    reason = " ".join(context.args) if getattr(context, "args", None) else "(no reason provided)"
    await context.bot.send_message(update.effective_chat.id, "Thanks—we have notified the admins.")
    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(admin_id,
                f"[REPORT] Chat {update.effective_chat.id} from @{update.effective_user.username or update.effective_user.id}: {reason}")
        except Exception as e:
            logger.debug(f"Notify admin failed: {e}")

async def cmd_warnings(update: Update, context):
    count = USER_WARNINGS.get((update.effective_chat.id, update.effective_user.id), 0)
    await context.bot.send_message(update.effective_chat.id, f"Your current warnings: {count}")

async def cmd_ping(update: Update, context):
    try:
        await context.bot.send_message(update.effective_chat.id, "🏓 pong")
    except Exception as e:
        logger.error(f"/ping send_message failed in chat {update.effective_chat.id}: {e}")

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
    await context.bot.send_message(update.effective_chat.id, text, parse_mode="Markdown")

# ----------------- Admin policy controls -----------------
async def enforce_admin_violation(update: Update, context, action_label: str = "change bot settings"):
    """Delete the offending command, warn the user, and optionally mute."""
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    await delete_message_safe(update, context)

    total = add_warning(chat_id, user_id)
    if total >= WARN_LIMIT:
        try:
            await context.bot.send_message(
                chat_id,
                f"🚫 You are not allowed to {action_label}. Muted for {MUTE_SECONDS}s."
            )
        except Exception:
            pass
        await restrict_user(chat_id, user_id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
    else:
        try:
            await context.bot.send_message(
                chat_id,
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
    if not getattr(context, "args", None):
        await context.bot.send_message(update.effective_chat.id, "Usage: /addbadword <word>")
        return
    for w in context.args:
        BAD_WORDS.add(w.lower())
    await context.bot.send_message(update.effective_chat.id, f"Added: {', '.join(context.args)}")

async def removebadword(update: Update, context):
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await enforce_admin_violation(update, context, action_label="change bot settings (/removebadword)")
        return
    if not getattr(context, "args", None):
        await context.bot.send_message(update.effective_chat.id, "Usage: /removebadword <word>")
        return
    removed = []
    for w in context.args:
        wl = w.lower()
        if wl in BAD_WORDS:
            BAD_WORDS.remove(wl)
            removed.append(w)
    await context.bot.send_message(update.effective_chat.id, f"Removed: {', '.join(removed) if removed else '(none)'}")

async def togglelinks(update: Update, context):
    user_id = update.effective_user.id
    if not is_admin(user_id):
        await enforce_admin_violation(update, context, action_label="change bot settings (/togglelinks)")
        return
    global BLOCK_LINKS
    BLOCK_LINKS = not BLOCK_LINKS
    await context.bot.send_message(update.effective_chat.id, f"Link blocking is now {'ON' if BLOCK_LINKS else 'OFF'}.")

# ----------------- Verification & Alerts -----------------
async def welcome_verify(update: Update, context):
    """Send join alert + start CAPTCHA gate."""
    chat_id = update.effective_chat.id
    for new_member in update.message.new_chat_members:
        # Gate: mark unverified & restrict until solved
        UNVERIFIED.add((chat_id, new_member.id))
        await restrict_user(chat_id, new_member.id, context, until_date=None)

        # CAPTCHA inline keyboard
        correct = random.randint(1, 4)
        options = list(range(1, 5))
        random.shuffle(options)
        keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify:{new_member.id}:{int(n==correct)}")] for n in options]
        PENDING_CAPTCHA[new_member.id] = {"chat_id": chat_id, "answer": correct}

        # Alert with details in the group
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
            f"• language_code: {lang}\n\n"
            f"Please verify: pick **{correct}** to unlock chatting.\n"
            f"UID: `{new_member.id}`"
        )
        await context.bot.send_message(chat_id, alert_text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

async def handle_join_request(update: Update, context):
    req = update.chat_join_request
    chat_id = req.chat.id
    user_id = req.from_user.id
    UNVERIFIED.add((chat_id, user_id))
    logger.info(f"JOIN REQUEST: marked UNVERIFIED {(chat_id, user_id)}")

# ----------------- Moderation -----------------
async def moderate(update: Update, context):
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
        await context.bot.send_message(chat_id, f"⌛ Slow down, @{user.username or user.first_name} (muted {MUTE_SECONDS}s).")
        await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
        return

    # Bad words
    if any(bad in text.lower() for bad in BAD_WORDS):
        await delete_message_safe(update, context)
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await context.bot.send_message(chat_id, f"🚫 Keep it civil. Muted for {MUTE_SECONDS}s.")
            await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
        else:
            await context.bot.send_message(chat_id, f"⚠️ Warning ({total}/{WARN_LIMIT}). Avoid offensive language.")
        return

    # Links
    if BLOCK_LINKS and contains_link(text):
        await delete_message_safe(update, context)
        await context.bot.send_message(chat_id, "🔗 Links are not allowed here. If it’s class-related, ask an admin.")
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))

# ----------------- VirusTotal scanning -----------------
async def vt_scan_and_report(file_path: str, progress_msg):
    if requests is None:
        await progress_msg.edit_text("❌ The 'requests' library is not installed. Add it to requirements.txt and redeploy.")
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
    """Scan any document (group or DM)."""
    doc = update.message.document
    file = await doc.get_file()
    file_path = await file.download_to_drive()
    progress_msg = await context.bot.send_message(update.effective_chat.id, "⏳ Uploading file to VirusTotal and starting scan...")
    await vt_scan_and_report(file_path, progress_msg)

async def scan_photo(update: Update, context):
    """Scan any photo (group or DM)."""
    photo = update.message.photo[-1]
    file = await photo.get_file()
    file_path = await file.download_to_drive()
    progress_msg = await context.bot.send_message(update.effective_chat.id, "⏳ Uploading image to VirusTotal and starting scan...")
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
    ChatMemberHandler, ChatJoinRequestHandler, filters, AIORateLimiter, Defaults
)
from telegram.constants import MessageEntityType

logger.info(f"Python: {sys.version}")
logger.info(f"python-telegram-bot: {telegram.__version__}")
logger.info(f"RENDER_EXTERNAL_URL: {os.getenv('RENDER_EXTERNAL_URL')}")
logger.info(f"WEBHOOK_URL: {WEBHOOK_URL or '(empty)'}")

builder = (
    ApplicationBuilder()
    .token(BOT_TOKEN)
    .updater(None)                   # custom webhook (PTB example)
    .defaults(Defaults(block=False)) # allow multiple handlers per update
)
try:
    builder = builder.rate_limiter(AIORateLimiter())
except Exception as e:
    logger.warning(f"AIORateLimiter unavailable ({e}); starting without rate limiter.")

application = builder.build()
bot_for_update = application.bot
BOT_USERNAME = None

async def on_error(update: object, context):
    logger.error("Handler error", exc_info=context.error)
application.add_error_handler(on_error)

# Diagnostics
application.add_handler(MessageHandler(filters.ALL, log_all_updates), group=-1)

# Gate first (non-blocking)
group_chats_filter_v20 = (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP)
application.add_handler(
    MessageHandler(group_chats_filter_v20 & filters.ALL, gate_unverified, block=False),
    group=0,
)

# Commands (explicit block=False; group=1)
application.add_handler(CommandHandler("start", cmd_start, block=False), group=1)
application.add_handler(CommandHandler("rules", cmd_rules, block=False), group=1)
application.add_handler(CommandHandler("report", cmd_report, block=False), group=1)
application.add_handler(CommandHandler("warnings", cmd_warnings, block=False), group=1)
application.add_handler(CommandHandler("function", cmd_function, block=False), group=1)
application.add_handler(CommandHandler("ping", cmd_ping, block=False), group=1)
application.add_handler(CommandHandler("addbadword", addbadword, block=False), group=1)
application.add_handler(CommandHandler("removebadword", removebadword, block=False), group=1)
application.add_handler(CommandHandler("togglelinks", togglelinks, block=False), group=1)

# Universal scan handlers (group & DM) — group=1 so they run alongside commands
application.add_handler(MessageHandler(filters.Document.ALL, scan_document, block=False), group=1)  # scans docs anywhere
application.add_handler(MessageHandler(filters.PHOTO,         scan_photo,    block=False), group=1)  # scans photos anywhere
# Filters reference: v20+ filters.Document.ALL, filters.PHOTO catch documents/photos respectively.  # docs
#                                                                                                   # see references below

# Group command tap (after commands)
async def group_command_tap(update: Update, context):
    msg = update.message
    txt = msg.text or ""
    ents = msg.entities or []
    target = None
    for e in ents:
        if e.type == MessageEntityType.BOT_COMMAND:
            cmd = txt[e.offset:e.offset + e.length]
            if '@' in cmd:
                target = cmd.split('@', 1)[1]
            break
    try:
        me = await context.bot.get_me()
        cm = await context.bot.get_chat_member(update.effective_chat.id, me.id)
        logger.info(f"GROUP COMMAND SEEN: text={txt!r}, target={target!r}, our_username={BOT_USERNAME!r}, "
                    f"chat_id={update.effective_chat.id}, bot_status={cm.status}")
    except Exception as e:
        logger.debug(f"get_chat_member failed: {e}")

application.add_handler(MessageHandler(filters.COMMAND & group_chats_filter_v20, group_command_tap), group=2)

# Moderation / join / scanners
application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, moderate))
application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, welcome_verify))  # join alert to group
application.add_handler(ChatJoinRequestHandler(handle_join_request))
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

    try:
        me = await application.bot.get_me()
        global BOT_USERNAME
        BOT_USERNAME = me.username
        logger.info(f"Bot identity: id={me.id}, username=@{BOT_USERNAME}")
    except Exception as e:
        logger.warning(f"get_me failed: {e}")

    await application.initialize()
    await application.start()

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
    logger.info(f"Starting Uvicorn on 0.0.0.0:{port}")
    try:
        uvicorn.run(app, host="0.0.0.0", port=port, workers=1)
    except Exception as e:
        logger.exception(f"Fatal error starting Uvicorn: {e}")
