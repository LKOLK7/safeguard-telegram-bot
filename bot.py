
#!/usr/bin/env python
import os, re, sys, random, logging, asyncio, string
from datetime import datetime, timedelta

# Optional dependency for VirusTotal
try:
    import requests
except ImportError:
    requests = None

from telegram import (
    Update, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
)
from telegram.helpers import escape_markdown
import telegram

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

# ------------- Logging -------------
logging.basicConfig(format="%(asctime)s %(levelname)s %(name)s %(message)s", level=logging.INFO)
logger = logging.getLogger("safeguard-bot")

# ------------- Environment -------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()}
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "change-me")
BASE_URL = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")
WEBHOOK_PATH = "/webhook"
WEBHOOK_URL = f"{BASE_URL}{WEBHOOK_PATH}" if BASE_URL else ""
VT_API_KEY = os.getenv("VT_API_KEY", "")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing.")

# VirusTotal API
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
PENDING_CAPTCHA = {}   # user_id -> {"chat_id": ..., "answer": ..., "mode": "post"|"pre", "token": ...}
PENDING_JOIN = {}      # token -> {"chat_id": ..., "user_id": ...}
USER_WARNINGS = {}     # (chat_id, user_id) -> count
USER_MSG_TIMES = {}    # (chat_id, user_id) -> timestamps
UNVERIFIED = set()     # {(chat_id, user_id)}
BOT_USERNAME = None    # filled at startup

ENGINES_FOR_PROGRESS = [
    "Kaspersky","Avast","BitDefender","ESET-NOD32","Microsoft","Sophos","TrendMicro",
    "McAfee","DrWeb","Fortinet","ClamAV","Paloalto","Malwarebytes","VIPRE"
]

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

URL_REGEX = re.compile(
    r"(https?://\S+|www\.\S+|t\.me/\S+|telegram\.me/\S+|@\w+)",
    re.IGNORECASE
)

def contains_link(text: str) -> bool:
    return bool(URL_REGEX.search(text or ""))

def secret_is_valid(token: str) -> bool:
    return bool(re.match(r'^[A-Za-z0-9_\-]{1,256}$', token))

def gen_token(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return "".join(random.choice(alphabet) for _ in range(length))

# ------------- Helpers (async) -------------
async def delete_message_safe(update: Update, context):
    try:
        await context.bot.delete_message(update.effective_chat.id, update.effective_message.message_id)
        logger.info(f"Deleted message {update.effective_message.message_id} in chat {update.effective_chat.id}")
    except Exception as e:
        logger.warning(f"Delete failed: {e}")

async def restrict_user(chat_id: int, user_id: int, context, until_date=None):
    # PTB >= 20.5: granular fields (no can_send_media_messages)
    perms = ChatPermissions(
        can_send_messages=False,
        can_send_polls=False,
        can_send_other_messages=False,
        can_add_web_page_previews=False,
        can_send_audios=False,
        can_send_documents=False,
        can_send_photos=False,
        can_send_videos=False,
        can_send_video_notes=False,
        can_send_voice_notes=False,
    )
    try:
        await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms, until_date=until_date)
        logger.info(f"Restricted user {user_id} in chat {chat_id}")
    except Exception as e:
        logger.warning(f"Restrict failed: {e}")

async def unrestrict_user(chat_id: int, user_id: int, context):
    # Re-enable typical messaging capabilities
    perms = ChatPermissions(
        can_send_messages=True,
        can_send_polls=True,
        can_send_other_messages=True,
        can_add_web_page_previews=True,
        can_send_audios=True,
        can_send_documents=True,
        can_send_photos=True,
        can_send_videos=True,
        can_send_video_notes=True,
        can_send_voice_notes=True,
    )
    try:
        await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms)
        logger.info(f"Unrestricted user {user_id} in chat {chat_id}")
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

async def notify_admins(context, text: str, parse_mode=None):
    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(admin_id, text, parse_mode=parse_mode)
        except Exception as e:
            logger.debug(f"notify_admins failed for {admin_id}: {e}")

# ------------- Diagnostics -------------
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

# ------------- Commands -------------
async def cmd_start(update: Update, context):
    logger.info(f"[HANDLER] /start fired in chat_id={update.effective_chat.id}")

    # Handle deep-link payloads for pre-join verification: /start join-<token>
    payload = None
    if update.message and update.message.text:
        parts = update.message.text.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0] == "/start":
            payload = parts[1].strip()

    if payload and payload.startswith("join-"):
        token = payload.split("join-", 1)[1].strip()
        pending = PENDING_JOIN.get(token)
        if not pending:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="⚠️ Verification link is invalid or expired. Please request to join again."
            )
            return

        # Issue a private CAPTCHA
        correct = random.randint(1, 4)
        options = list(range(1, 5)); random.shuffle(options)
        keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify_join:{token}:{int(n==correct)}")] for n in options]

        # Track pending per user
        PENDING_CAPTCHA[update.effective_user.id] = {
            "chat_id": pending["chat_id"],
            "answer": correct,
            "mode": "pre",
            "token": token
        }

        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="🔐 Please solve the CAPTCHA to join the group. Pick the correct number:",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    # Default intro
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=(
            "Hello! I keep this group safe—moderation, anti‑spam, and new member verification.\n"
            "Use /rules to see the code of conduct, /function to see all features, or /report to alert admins.\n\n"
            "You can also send a file or photo and I’ll **scan it with VirusTotal** to check for malware."
        )
    )

async def cmd_rules(update: Update, context):
    await context.bot.send_message(
        update.effective_chat.id,
        "Group rules:\n• Be respectful.\n• No profanity or harassment.\n• Avoid spam & unsolicited ads.\n"
        "• External links only when relevant.\n• Follow lecturer’s guidance."
    )

async def cmd_report(update: Update, context):
    reason = " ".join(context.args) if getattr(context, "args", None) else "(no reason provided)"
    await context.bot.send_message(update.effective_chat.id, "Thanks—we have notified the admins.")
    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(
                admin_id,
                f"[REPORT] Chat {update.effective_chat.id} from @{update.effective_user.username or update.effective_user.id}: {reason}"
            )
        except Exception:
            pass

async def cmd_warnings(update: Update, context):
    count = USER_WARNINGS.get((update.effective_chat.id, update.effective_user.id), 0)
    await context.bot.send_message(update.effective_chat.id, f"Your current warnings: {count}")

async def cmd_ping(update: Update, context):
    await context.bot.send_message(update.effective_chat.id, "🏓 pong")

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
        "• Pre‑join: CAPTCHA via Join Requests; auto‑approval on success\n"
        "• Post‑join: new members must pass a simple CAPTCHA to chat\n"
        "• Instant admin alert with user details when someone joins or requests to join\n\n"
        "**Admin Controls**\n"
        "• /addbadword <word ...> – Add banned words (admins only)\n"
        "• /removebadword <word ...> – Remove banned words (admins only)\n"
        "• /togglelinks – Enable/disable link blocking (admins only)\n\n"
        "**Security Scanner**\n"
        "• Send a **file** or **photo** to automatically scan with **VirusTotal** and get a readable summary.\n"
        " (Public API has rate limits; use wisely.)"
    )
    await context.bot.send_message(update.effective_chat.id, text, parse_mode="Markdown")

async def cmd_diagnose(update: Update, context):
    chat_id = update.effective_chat.id
    try:
        me = await context.bot.get_me()
        cm = await context.bot.get_chat_member(chat_id, me.id)
        text = [
            f"Bot username: {me.username}",
            f"Bot role in this chat: {cm.status}",
            f"Can delete messages: {getattr(cm, 'can_delete_messages', False)}",
            f"Can restrict/ban users: {getattr(cm, 'can_restrict_members', False)}",
            f"Webhook URL: {WEBHOOK_URL or '(empty)'}",
            f"WEBHOOK_SECRET enabled: {bool(WEBHOOK_SECRET)}",
            f"ADMIN_IDS loaded: {sorted(list(ADMIN_IDS))}",
        ]
        await context.bot.send_message(chat_id, "\n".join(text))
    except Exception as e:
        await context.bot.send_message(chat_id, f"Diagnose error: {e}")

# ------------- Admin policy controls -------------
async def enforce_admin_violation(update: Update, context, action_label: str):
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id
    await delete_message_safe(update, context)
    total = add_warning(chat_id, user_id)
    if total >= WARN_LIMIT:
        await context.bot.send_message(chat_id, f"🚫 You are not allowed to {action_label}. Muted for {MUTE_SECONDS}s.")
        await restrict_user(chat_id, user_id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
    else:
        await context.bot.send_message(
            chat_id,
            f"⚠️ You are not allowed to {action_label}. Warning ({total}/{WARN_LIMIT}).\n"
            f"Further violations may result in a temporary mute."
        )

async def addbadword(update: Update, context):
    if not is_admin(update.effective_user.id):
        await enforce_admin_violation(update, context, "change bot settings (/addbadword)")
        return
    if not getattr(context, "args", None):
        await context.bot.send_message(update.effective_chat.id, "Usage: /addbadword <word>")
        return
    for w in context.args:
        BAD_WORDS.add(w.lower())
    await context.bot.send_message(update.effective_chat.id, f"Added: {', '.join(context.args)}")

async def removebadword(update: Update, context):
    if not is_admin(update.effective_user.id):
        await enforce_admin_violation(update, context, "change bot settings (/removebadword)")
        return
    if not getattr(context, "args", None):
        await context.bot.send_message(update.effective_chat.id, "Usage: /removebadword <word>")
        return
    removed = []
    for w in context.args:
        wl = w.lower()
        if wl in BAD_WORDS:
            BAD_WORDS.remove(wl); removed.append(w)
    await context.bot.send_message(update.effective_chat.id, f"Removed: {', '.join(removed) if removed else '(none)'}")

async def togglelinks(update: Update, context):
    if not is_admin(update.effective_user.id):
        await enforce_admin_violation(update, context, "change bot settings (/togglelinks)")
        return
    global BLOCK_LINKS
    BLOCK_LINKS = not BLOCK_LINKS
    await context.bot.send_message(update.effective_chat.id, f"Link blocking is now {'ON' if BLOCK_LINKS else 'OFF'}.")

# ------------- Gate -------------
async def gate_unverified(update: Update, context):
    chat = update.effective_chat
    user = update.effective_user
    msg = update.effective_message
    is_start_cmd = bool(msg and msg.text and msg.text.strip().startswith("/start"))
    if chat.type in ("group", "supergroup") and (chat.id, user.id) in UNVERIFIED and not is_start_cmd:
        await delete_message_safe(update, context)
        try:
            await context.bot.send_message(chat.id, f"⛔ @{user.username or user.first_name}, please complete the CAPTCHA above to start chatting.")
        except Exception:
            pass

# ------------- Moderation -------------
async def moderate(update: Update, context):
    msg = update.effective_message
    user = msg.from_user
    chat_id = update.effective_chat.id
    text = (msg.text or msg.caption or "")

    if is_admin(user.id): return

    if record_user_message(chat_id, user.id) > FLOOD_MAX_MSG:
        await delete_message_safe(update, context)
        await context.bot.send_message(chat_id, f"⌛ Slow down, @{user.username or user.first_name} (muted {MUTE_SECONDS}s).")
        await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
        return

    if any(bad in text.lower() for bad in BAD_WORDS):
        await delete_message_safe(update, context)
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await context.bot.send_message(chat_id, f"🚫 Keep it civil. Muted for {MUTE_SECONDS}s.")
            await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
        else:
            await context.bot.send_message(chat_id, f"⚠️ Warning ({total}/{WARN_LIMIT}). Avoid offensive language.")
        return

    if BLOCK_LINKS and contains_link(text):
        await delete_message_safe(update, context)
        await context.bot.send_message(chat_id, "🔗 Links are not allowed here. If it’s class-related, ask an admin.")
        total = add_warning(chat_id, user.id)
        if total >= WARN_LIMIT:
            await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))

# ------------- Join alert + CAPTCHA (Post-join) -------------
async def welcome_verify(update: Update, context):
    chat_id = update.effective_chat.id
    chat_title = update.effective_chat.title or str(chat_id)

    for new_member in update.message.new_chat_members:
        logger.info(f"NEW_CHAT_MEMBER: {new_member.id} joined chat {chat_id}")
        UNVERIFIED.add((chat_id, new_member.id))
        await restrict_user(chat_id, new_member.id, context, until_date=None)

        # Build in-group CAPTCHA
        correct = random.randint(1, 4)
        options = list(range(1, 5)); random.shuffle(options)
        keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify:{new_member.id}:{int(n==correct)}")] for n in options]
        PENDING_CAPTCHA[new_member.id] = {"chat_id": chat_id, "answer": correct, "mode": "post", "token": None}

        # Group alert with basic details
        uid = new_member.id
        isbot = "true" if new_member.is_bot else "false"
        fn = new_member.first_name or "-"
        ln = new_member.last_name or "-"
        un = new_member.username or "-"
        link = f"(https://t.me/{new_member.username})" if new_member.username else "(-)"
        lang = getattr(new_member, "language_code", None) or "-"

        alert_group = (
            "📣 NEW MEMBER ALERT\n"
            f"• Group: {chat_title} ({chat_id})\n"
            f"• UID: {uid}\n• is_bot: {isbot}\n• first_name: {fn}\n• last_name: {ln}\n"
            f"• username: {un} {link}\n• language_code: {lang}\n\n"
            f"Please verify: pick **{correct}** to unlock chatting.\nUID: `{new_member.id}`"
        )
        await context.bot.send_message(chat_id, alert_group, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

        # Admin DM alert
        alert_admin = (
            "🔔 NEW MEMBER JOINED\n"
            f"• Group: {chat_title} ({chat_id})\n"
            f"• UID: {uid}\n• username: {un}\n• Name: {fn} {ln}\n"
            "A post‑join CAPTCHA has been posted and the user is currently restricted."
        )
        await notify_admins(context, alert_admin)

# ------------- Join Request (Pre-join verification) -------------
async def handle_join_request(update: Update, context):
    req = update.chat_join_request
    chat_id = req.chat.id
    chat_title = req.chat.title or str(chat_id)
    user = req.from_user

    # Create one-time token + deep-link for verification
    token = gen_token()
    PENDING_JOIN[token] = {"chat_id": chat_id, "user_id": user.id}

    deep_link = None
    if BOT_USERNAME:
        deep_link = f"https://t.me/{BOT_USERNAME}?start=join-{token}"

    UNVERIFIED.add((chat_id, user.id))
    logger.info(f"JOIN REQUEST: stored token {token} for {(chat_id, user.id)}")

    # Try DM the user (may fail if user hasn’t started the bot)
    dm_text = (
        "👋 You requested to join the group.\n"
        "Please complete the CAPTCHA to get approved.\n\n"
        f"➡️ Tap this link to start verification: {deep_link or 'Open the bot and send /start join-'+token}"
    )
    try:
        await context.bot.send_message(user.id, dm_text)
    except Exception as e:
        logger.debug(f"DM to user failed (likely user never started bot): {e}")

    # Admin alert with deep-link (so admins can remind the user)
    admin_text = (
        "🔔 NEW JOIN REQUEST\n"
        f"• Group: {chat_title} ({chat_id})\n"
        f"• UID: {user.id}\n• username: {user.username or '-'}\n• Name: {user.first_name or '-'} {user.last_name or '-'}\n\n"
        "Pre‑join verification required. If the user cannot receive DMs, ask them to start the bot and click:\n"
        f"{deep_link or '(bot username not yet known; user should open the bot and send /start join-'+token+')'}"
    )
    await notify_admins(context, admin_text)

# ------------- VirusTotal scanning -------------
async def vt_scan_and_report(file_path: str, progress_msg):
    if requests is None:
        await progress_msg.edit_text("❌ 'requests' not installed. Add it to requirements.txt and redeploy."); return
    if not VT_API_KEY:
        await progress_msg.edit_text("❌ VirusTotal API key (VT_API_KEY) not configured."); return
    try:
        with open(file_path, "rb") as f:
            resp = requests.post(VT_FILE_SCAN_URL, headers=VT_HEADERS, files={"file": f})
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id")
            if not analysis_id:
                await progress_msg.edit_text("❌ Failed to get analysis ID from VirusTotal."); return
            await progress_msg.edit_text("✅ File uploaded! Scanning in progress...")
    except Exception as e:
        await progress_msg.edit_text(f"❌ Upload error: {escape_markdown(str(e), version=2)}", parse_mode="MarkdownV2"); return

    idx, prev, attempts, max_attempts = 0, None, 0, 120
    while attempts < max_attempts:
        await asyncio.sleep(5)
        try:
            s = requests.get(VT_ANALYSES_URL_TPL.format(analysis_id), headers=VT_HEADERS)
            s.raise_for_status()
            attrs = s.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                results = attrs.get("results", {})
                malicious, suspicious, clean = [], [], []
                for engine, det in results.items():
                    cat = det.get("category"); res = det.get("result")
                    if cat == "malicious": malicious.append(f"• {engine}: {res}")
                    elif cat == "suspicious": suspicious.append(f"• {engine}: {res or 'Suspicious'}")
                    else: clean.append(f"• {engine}: clean")
                grouped = "──────────────\n"
                if malicious: grouped += "🔴 *Malicious:*\n" + "\n".join(malicious) + "\n\n"
                if suspicious: grouped += "🟠 *Suspicious:*\n" + "\n".join(suspicious) + "\n\n"
                if clean: grouped += "✅ *Clean:*\n" + "\n".join(clean) + "\n"
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
                try: os.remove(file_path)
                except Exception as e: logger.error(f"Delete temp file failed: {e}")
                return

            banner = f"🔎 Scanning... please wait ({ENGINES_FOR_PROGRESS[idx]})"
            if banner != prev:
                await progress_msg.edit_text(banner); prev = banner
            idx = (idx + 1) % len(ENGINES_FOR_PROGRESS)
            attempts += 1
        except Exception as e:
            logger.error(f"VT status error: {e}"); attempts += 1

    await progress_msg.edit_text("⚠️ Scan taking too long. Please check manually on VirusTotal.")
    try: os.remove(file_path)
    except Exception as e: logger.error(f"Delete temp after timeout failed: {e}")

async def scan_document(update: Update, context):
    doc = update.message.document
    file = await doc.get_file()
    path = await file.download_to_drive()
    progress = await context.bot.send_message(update.effective_chat.id, "⏳ Uploading file to VirusTotal and starting scan...")
    await vt_scan_and_report(path, progress)

async def scan_photo(update: Update, context):
    photo = update.message.photo[-1]
    file = await photo.get_file()
    path = await file.download_to_drive()
    progress = await context.bot.send_message(update.effective_chat.id, "⏳ Uploading image to VirusTotal and starting scan...")
    await vt_scan_and_report(path, progress)

# ------------- Verify button (both modes) -------------
async def verify_callback(update: Update, context):
    q = update.callback_query; await q.answer()
    try:
        if q.data.startswith("verify:"):
            # Post-join in-group verification
            _, uid_str, ok_str = q.data.split(":")
            user_id = int(uid_str); is_ok = bool(int(ok_str))
            pending = PENDING_CAPTCHA.get(user_id)
            if not pending:
                await q.edit_message_text("No active verification."); return
            chat_id = pending["chat_id"]
            if q.from_user.id != user_id:
                await q.edit_message_text("This verification is not for you."); return
            if is_ok:
                await unrestrict_user(chat_id, user_id, context)
                UNVERIFIED.discard((chat_id, user_id))
                await q.edit_message_text("✅ Verified. Welcome!")
                PENDING_CAPTCHA.pop(user_id, None)
            else:
                await q.edit_message_text("❌ Wrong answer. Try again.")

        elif q.data.startswith("verify_join:"):
            # Pre-join private verification
            _, token, ok_str = q.data.split(":")
            is_ok = bool(int(ok_str))
            pending_join = PENDING_JOIN.get(token)
            if not pending_join:
                await q.edit_message_text("Verification expired. Please request to join again."); return
            chat_id = pending_join["chat_id"]
            user_id = pending_join["user_id"]
            if q.from_user.id != user_id:
                await q.edit_message_text("This verification is not for you."); return

            if is_ok:
                try:
                    await context.bot.approve_chat_join_request(chat_id, user_id)
                    UNVERIFIED.discard((chat_id, user_id))
                except Exception as e:
                    logger.warning(f"approve_chat_join_request failed: {e}")
                await q.edit_message_text("✅ Verified. Your join request has been approved. Welcome!")
                PENDING_JOIN.pop(token, None)
                PENDING_CAPTCHA.pop(user_id, None)
            else:
                # Re-issue the same keyboard to retry
                correct = PENDING_CAPTCHA.get(user_id, {}).get("answer", random.randint(1, 4))
                options = list(range(1, 5)); random.shuffle(options)
                keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify_join:{token}:{int(n==correct)}")] for n in options]
                # Update stored answer
                PENDING_CAPTCHA[user_id] = {"chat_id": chat_id, "answer": correct, "mode": "pre", "token": token}
                await q.edit_message_text("❌ Wrong answer. Try again:", reply_markup=InlineKeyboardMarkup(keyboard))
    except Exception as e:
        logger.debug(f"verify_callback error: {e}")

# ------------- PTB + Starlette -------------
from telegram.ext import (
    ApplicationBuilder, MessageHandler, CommandHandler, CallbackQueryHandler,
    ChatJoinRequestHandler, filters, AIORateLimiter, Defaults
)
from telegram.constants import MessageEntityType

logger.info(f"Python: {sys.version}")
logger.info(f"python-telegram-bot: {telegram.__version__}")
logger.info(f"RENDER_EXTERNAL_URL: {os.getenv('RENDER_EXTERNAL_URL')}")
logger.info(f"WEBHOOK_URL: {WEBHOOK_URL or '(empty)'}")

builder = (
    ApplicationBuilder()
    .token(BOT_TOKEN)
    .updater(None)     # custom webhook pattern
    .defaults(Defaults(block=False))  # non-blocking handlers
)
try:
    builder = builder.rate_limiter(AIORateLimiter())
except Exception as e:
    logger.warning(f"AIORateLimiter unavailable ({e}); starting without rate limiter.")

application = builder.build()
bot_for_update = application.bot

# Global error logger
async def on_error(update: object, context):
    logger.error("Handler error", exc_info=context.error)

application.add_error_handler(on_error)

# ----- Handler registrations (AFTER functions) -----
application.add_handler(MessageHandler(filters.ALL, log_all_updates), group=-1)
group_chats_filter_v20 = (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP)

application.add_handler(MessageHandler(group_chats_filter_v20 & filters.ALL, gate_unverified, block=False), group=0)

application.add_handler(CommandHandler("start", cmd_start, block=False), group=1)
application.add_handler(CommandHandler("rules", cmd_rules, block=False), group=1)
application.add_handler(CommandHandler("report", cmd_report, block=False), group=1)
application.add_handler(CommandHandler("warnings", cmd_warnings, block=False), group=1)
application.add_handler(CommandHandler("function", cmd_function, block=False), group=1)
application.add_handler(CommandHandler("ping", cmd_ping, block=False), group=1)
application.add_handler(CommandHandler("addbadword", addbadword, block=False), group=1)
application.add_handler(CommandHandler("removebadword", removebadword, block=False), group=1)
application.add_handler(CommandHandler("togglelinks", togglelinks, block=False), group=1)
application.add_handler(CommandHandler("diagnose", cmd_diagnose, block=False), group=1)

application.add_handler(MessageHandler(filters.Document.ALL, scan_document, block=False), group=1)
application.add_handler(MessageHandler(filters.PHOTO, scan_photo, block=False), group=1)

# Post-join flow
application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, welcome_verify), group=1)

# Pre-join flow
application.add_handler(ChatJoinRequestHandler(handle_join_request), group=1)

# Unified verification callback
application.add_handler(CallbackQueryHandler(verify_callback, pattern=r"^(verify:|verify_join:)"), group=1)

# Moderation
application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, moderate), group=1)

# ----- Command tap (optional log) -----
async def group_command_tap(update: Update, context):
    msg = update.message; txt = msg.text or ""; ents = msg.entities or []
    target = None
    for e in ents:
        if e.type == MessageEntityType.BOT_COMMAND:
            cmd = txt[e.offset:e.offset + e.length]
            target = cmd.split('@', 1)[1] if '@' in cmd else None
            break
    try:
        me = await context.bot.get_me()
        cm = await context.bot.get_chat_member(update.effective_chat.id, me.id)
        logger.info(f"GROUP COMMAND SEEN: text={txt!r}, target={target!r}, chat_id={update.effective_chat.id}, bot_status={cm.status}")
    except Exception as e:
        logger.debug(f"get_chat_member failed: {e}")

application.add_handler(MessageHandler(filters.COMMAND & group_chats_filter_v20, group_command_tap), group=2)

# ----- Commands menu -----
async def set_my_commands():
    try:
        cmds = [
            BotCommand("start","Introduction"),
            BotCommand("rules","Show group rules"),
            BotCommand("report","Report an issue to admins"),
            BotCommand("warnings","Show your warnings"),
            BotCommand("function","Show all bot functions"),
            BotCommand("ping","Quick connectivity test"),
            BotCommand("diagnose","Show bot permissions & config"),
        ]
        await application.bot.set_my_commands(cmds)
    except Exception as e:
        logger.debug(f"set_my_commands failed: {e}")

# ----- Starlette app & webhook -----
async def healthz(request: Request): return JSONResponse({"status":"ok"})
async def root(request: Request): return PlainTextResponse("OK", status_code=200)

async def webhook(request: Request) -> Response:
    # Optional secret header check
    if secret_is_valid(WEBHOOK_SECRET):
        if request.headers.get("X-Telegram-Bot-Api-Secret-Token") != WEBHOOK_SECRET:
            logger.warning("Forbidden: secret mismatch"); return PlainTextResponse("forbidden", status_code=403)
    try: data = await request.json()
    except Exception: return PlainTextResponse("bad request", status_code=400)
    await application.update_queue.put(Update.de_json(data=data, bot=bot_for_update))
    return Response()

routes = [
    Route("/", root, methods=["GET"]),
    Route("/healthz", healthz, methods=["GET"]),
    Route(WEBHOOK_PATH, webhook, methods=["POST"])
]
app = Starlette(routes=routes)

# ----- Async main: start PTB + Uvicorn and SERVE (blocks) -----
async def main():
    import uvicorn
    port = int(os.getenv("PORT", "10000"))
    logger.info(f"Starting Uvicorn on 0.0.0.0:{port}")
    config = uvicorn.Config(app=app, host="0.0.0.0", port=port, workers=1, log_level="info")
    server = uvicorn.Server(config)

    await application.initialize()
    await application.start()

    # Resolve bot username for deep-links
    global BOT_USERNAME
    try:
        me = await application.bot.get_me()
        BOT_USERNAME = me.username
        logger.info(f"BOT_USERNAME resolved: {BOT_USERNAME}")
    except Exception as e:
        logger.warning(f"Failed to resolve BOT_USERNAME: {e}")

    # set webhook (non-fatal on error)
    try:
        if WEBHOOK_URL:
            if secret_is_valid(WEBHOOK_SECRET):
                await application.bot.set_webhook(
                    url=WEBHOOK_URL, secret_token=WEBHOOK_SECRET,
                    allowed_updates=Update.ALL_TYPES, drop_pending_updates=True
                )
            else:
                await application.bot.set_webhook(
                    url=WEBHOOK_URL, allowed_updates=Update.ALL_TYPES, drop_pending_updates=True
                )
            logger.info(f"Webhook set to {WEBHOOK_URL}")
        else:
            logger.warning("WEBHOOK_URL empty; skipping set_webhook.")
    except Exception as e:
        logger.error(f"set_webhook failed: {e}")

    await set_my_commands()

    # BLOCK here
    await server.serve()

    # graceful stop
    await application.stop()
    await application.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
