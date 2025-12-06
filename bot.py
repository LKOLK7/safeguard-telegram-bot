
#!/usr/bin/env python
import os, re, sys, random, logging, asyncio, string, base64, json, unicodedata
from datetime import datetime, timedelta
from typing import Optional, List, Tuple
from urllib.parse import urlparse

# Optional dependency for external APIs
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

# API keys
VT_API_KEY = os.getenv("VT_API_KEY", "")
GSB_API_KEY = os.getenv("GSB_API_KEY", "")
PERSPECTIVE_API_KEY = os.getenv("PERSPECTIVE_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing.")

# ---- API endpoints ----
VT_BASE = "https://www.virustotal.com/api/v3"
GSB_LOOKUP = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
ABUSEIPDB_CHECK = "https://api.abuseipdb.com/api/v2/check"
PERSPECTIVE_ANALYZE = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"

# Policies
BAD_WORDS = {"idiot", "stupid", "fool"}
BLOCK_LINKS = True
WARN_LIMIT = 2
FLOOD_MAX_MSG = 5
FLOOD_WINDOW_SEC = 10
MUTE_SECONDS = 60

# Risk thresholds (tune via env if desired)
TOXICITY_THRESHOLD = float(os.getenv("TOXICITY_THRESHOLD", "0.85"))
SEVERE_TOXICITY_THRESHOLD = float(os.getenv("SEVERE_TOXICITY_THRESHOLD", "0.75"))
INSULT_THRESHOLD = float(os.getenv("INSULT_THRESHOLD", "0.85"))
THREAT_THRESHOLD = float(os.getenv("THREAT_THRESHOLD", "0.60"))
ABUSEIPDB_CONFIDENCE_MIN = int(os.getenv("ABUSEIPDB_CONFIDENCE_MIN", "75"))

# State (in-memory only; no persistence)
PENDING_CAPTCHA = {}  # user_id -> {"chat_id": ..., "answer": ..., "mode": "post"|"pre", "token": ...}
PENDING_JOIN = {}     # token -> {"chat_id": ..., "user_id": ...}
USER_WARNINGS = {}    # (chat_id, user_id) -> count
USER_MSG_TIMES = {}   # (chat_id, user_id) -> timestamps
UNVERIFIED = set()    # {(chat_id, user_id)}
BOT_USERNAME = None   # filled at startup
SESSION_USERNAMES: dict[int, Optional[str]] = {}

# Simple throttle for Perspective (~1 QPS default)
_last_perspective_call_ts = 0.0
PERSPECTIVE_MIN_INTERVAL = float(os.getenv("PERSPECTIVE_MIN_INTERVAL", "1.0"))

ENGINES_FOR_PROGRESS = [
    "Kaspersky","Avast","BitDefender","ESET-NOD32","Microsoft","Sophos","TrendMicro",
    "McAfee","DrWeb","Fortinet","ClamAV","Paloalto","Malwarebytes","VIPRE"
]

# ---- Preferred engines for summary (Top 1–Top 3) ----
DEFAULT_TOP_ENGINES = ["Microsoft", "Kaspersky", "BitDefender"]
TOP_ENGINES = [x.strip() for x in os.getenv("TOP_ENGINES", ",".join(DEFAULT_TOP_ENGINES)).split(",") if x.strip()]
TOP_ENGINES = (TOP_ENGINES or DEFAULT_TOP_ENGINES)[:3]

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

# ------------- Defang / Deobfuscation + URL/Domain extraction -------------

ZERO_WIDTH_PATTERN = re.compile(
    r"[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]"
)

DEFANG_REPLACEMENTS = [
    (re.compile(r"hxxps", re.I), "https"),
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"https\[\s*:\s*\]", re.I), "https:"),
    (re.compile(r"http\[\s*:\s*\]", re.I), "http:"),
    (re.compile(r"\[\s*:\s*\]//"), "://"),
    (re.compile(r"\(\s*:\s*\)//"), "://"),
    (re.compile(r"[:]\s*//"), "://"),
    (re.compile(r"\[\.\]", re.I), "."),
    (re.compile(r"\(\.\)", re.I), "."),
    (re.compile(r"\{\.\}", re.I), "."),
    (re.compile(r"\s+\.\s+"), "."),
    # common obfuscations of dot and at
    (re.compile(r"\s*\(\s*dot\s*\)\s*", re.I), "."),
    (re.compile(r"\s*\[\s*dot\s*\]\s*", re.I), "."),
    (re.compile(r"\s*{\s*dot\s*}\s*", re.I), "."),
    (re.compile(r"\s*\(\s*at\s*\)\s*", re.I), "@"),
    (re.compile(r"\s*\[\s*at\s*\]\s*", re.I), "@"),
    # remove spaces between domain tokens like 'g i t h u b . com'
    (re.compile(r"(?i)\b([a-z0-9])\s+(?=[a-z0-9])"), r"\1"),
]

# detect domains even without scheme, including t.me/ telegram.me/ etc.
DOMAIN_REGEX = re.compile(
    r"""
    (?<![\w])                                  # not preceded by word char
    (                                          # group domain
      (?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9omain
      |(?:t\.me|telegram\.me)                  # telegram short domains
      |localhost
    )
    (?:[:]\d{2,5})?                            # optional port
    (?:/[^\s]+)?                               # optional path
    """,
    re.IGNORECASE | re.VERBOSE,
)

URL_WITH_SCHEME_REGEX = re.compile(
    r"""
    (?i)
    \b
    (?:https?|ftp)://
    [^\s<>"]+
    """,
    re.VERBOSE,
)

def strip_zero_width(text: str) -> str:
    return ZERO_WIDTH_PATTERN.sub("", text or "")

def deobfuscate_text(text: str) -> str:
    t = strip_zero_width(text)
    for pat, repl in DEFANG_REPLACEMENTS:
        t = pat.sub(repl, t)
    # collapse excessive whitespace
    t = re.sub(r"\s{2,}", " ", t)
    return t

def extract_urls_and_domains(text: str) -> List[str]:
    """
    Returns normalized URLs (with scheme). Converts bare domains to http://domain.
    Handles defanged links and common obfuscations to prevent bypass.
    """
    if not text:
        return []
    t = deobfuscate_text(text)

    urls = set()

    # URLs that already have a scheme
    for m in URL_WITH_SCHEME_REGEX.finditer(t):
        u = m.group(0).rstrip(").,;!?'\"")
        urls.add(u)

    # Bare domains (no scheme) -> http://domain...
    for m in DOMAIN_REGEX.finditer(t):
        raw = m.group(0).rstrip(").,;!?'\"")
        # If the raw already starts with a scheme, skip (already captured)
        if not re.match(r"(?i)^(?:https?|ftp)://", raw):
            u = "http://" + raw
        else:
            u = raw
        urls.add(u)

    # Special handling for @username (telegram links)
    for m in re.finditer(r"(?i)@\w{5,}", t):
        username = m.group(0)[1:]
        urls.add(f"https://t.me/{username}")

    # Limit to reasonable count
    normalized = list(urls)
    # sanitize trailing punctuation again
    normalized = [u.rstrip(").,;!?'\"") for u in normalized]
    return normalized[:20]

# ------------- External checks -------------
def vt_url_id(url: str) -> str:
    raw = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return raw

def check_virustotal_url(url: str) -> Tuple[bool, str]:
    if not VT_API_KEY or requests is None: return (False, "VT disabled")
    headers = {"x-apikey": VT_API_KEY}
    try:
        uid = vt_url_id(url)
        g = requests.get(f"{VT_BASE}/urls/{uid}", headers=headers, timeout=8)
        if g.status_code == 404:
            requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=8)
            g = requests.get(f"{VT_BASE}/urls/{uid}", headers=headers, timeout=8)
        if g.status_code == 200:
            data = g.json().get("data", {}).get("attributes", {})
            verdicts = data.get("last_analysis_stats", {})
            malicious = int(verdicts.get("malicious", 0))
            suspicious = int(verdicts.get("suspicious", 0))
            if malicious > 0 or suspicious > 0:
                return (True, f"VirusTotal flags: malicious={malicious}, suspicious={suspicious}")
            return (False, "VirusTotal: clean/undetected")
        return (False, f"VirusTotal: status={g.status_code}")
    except Exception as e:
        return (False, f"VirusTotal error: {e}")

def check_google_safebrowsing(urls: List[str]) -> Tuple[bool, str]:
    if not GSB_API_KEY or requests is None or not urls: return (False, "GSB disabled")
    payload = {
        "client": {"clientId": "safeguard_bot", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }
    try:
        r = requests.post(f"{GSB_LOOKUP}?key={GSB_API_KEY}", json=payload, timeout=8)
        if r.status_code == 200:
            matches = r.json().get("matches", [])
            if matches:
                kinds = {m.get("threatType","UNKNOWN") for m in matches}
                return (True, f"Safe Browsing matches: {', '.join(sorted(kinds))} (Advisory provided by Google)")
            return (False, "Safe Browsing: no matches")
        return (False, f"Safe Browsing: status={r.status_code}")
    except Exception as e:
        return (False, f"Safe Browsing error: {e}")

def check_abuseipdb_ip(ip: str) -> Tuple[bool, str, int]:
    if not ABUSEIPDB_API_KEY or requests is None: return (False, "AbuseIPDB disabled", 0)
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        r = requests.get(ABUSEIPDB_CHECK, headers=headers, params=params, timeout=8)
        if r.status_code == 200:
            data = r.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            if score >= ABUSEIPDB_CONFIDENCE_MIN:
                return (True, f"AbuseIPDB: confidence={score}", score)
            return (False, f"AbuseIPDB: confidence={score}", score)
        return (False, f"AbuseIPDB: status={r.status_code}", 0)
    except Exception as e:
        return (False, f"AbuseIPDB error: {e}", 0)

async def analyze_toxicity(text: str) -> Optional[dict]:
    global _last_perspective_call_ts
    if not PERSPECTIVE_API_KEY or requests is None or not text: return None
    now = datetime.now().timestamp()
    if now - _last_perspective_call_ts < PERSPECTIVE_MIN_INTERVAL:  # ~1 QPS
        return None
    _last_perspective_call_ts = now
    payload = {
        "comment": {"text": text[:3000]},
        "languages": ["en"],  # adjust language if needed
        "requestedAttributes": {"TOXICITY": {}, "SEVERE_TOXICITY": {}, "INSULT": {}, "THREAT": {}}
    }
    try:
        r = requests.post(f"{PERSPECTIVE_ANALYZE}?key={PERSPECTIVE_API_KEY}", json=payload, timeout=8)
        if r.status_code == 200:
            out = r.json().get("attributeScores", {})
            return {k: float(v["summaryScore"]["value"]) for k, v in out.items() if "summaryScore" in v}
        logger.debug(f"Perspective status={r.status_code} body={r.text[:200]}")
        return None
    except Exception as e:
        logger.debug(f"Perspective error: {e}")
        return None

# ------------- Helpers (async) -------------
async def delete_message_safe(update: Update, context):
    try:
        await context.bot.delete_message(update.effective_chat.id, update.effective_message.message_id)
        logger.info(f"Deleted message {update.effective_message.message_id} in chat {update.effective_chat.id}")
    except Exception as e:
        logger.warning(f"Delete failed: {e}")

async def restrict_user(chat_id: int, user_id: int, context, until_date=None):
    perms = ChatPermissions(
        can_send_messages=False, can_send_polls=False, can_send_other_messages=False,
        can_add_web_page_previews=False, can_send_audios=False, can_send_documents=False,
        can_send_photos=False, can_send_videos=False, can_send_video_notes=False, can_send_voice_notes=False,
    )
    try:
        await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms, until_date=until_date)
        logger.info(f"Restricted user {user_id} in chat {chat_id}")
    except Exception as e:
        logger.warning(f"Restrict failed: {e}")

async def unrestrict_user(chat_id: int, user_id: int, context):
    perms = ChatPermissions(
        can_send_messages=True, can_send_polls=True, can_send_other_messages=True,
        can_add_web_page_previews=True, can_send_audios=True, can_send_documents=True,
        can_send_photos=True, can_send_videos=True, can_send_video_notes=True, can_send_voice_notes=True,
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

# ------------- NEW: Custom welcome message builder -------------
def build_welcome_message(name: str) -> str:
    return (
        f"👋 Welcome {name}! This bot helps keep our community safe and secure.\n\n"
        "🔐 **Security Features Enabled:**\n"
        "• **Post-Join Verification**: New members must pass a simple CAPTCHA before chatting.\n"
        "• **Link Safety Checks**: URLs are scanned using Google Safe Browsing and VirusTotal to block phishing or malware.\n"
        "• **IP Reputation Monitoring**: Detects risky IP addresses via AbuseIPDB.\n"
        "• **AI-Powered Moderation**: Messages are analyzed for toxicity, threats, and harassment using Perspective API.\n"
        "• **Automated Incident Response**: Suspicious content triggers immediate actions (delete, warn, mute) and alerts admins.\n\n"
        "✅ Please follow the group rules:\n"
        "• Be respectful and avoid offensive language.\n"
        "• No spam, scams, or suspicious links.\n"
        "• External links only when relevant and safe.\n\n"
        "📌 If you have questions or need help, use `/report <reason>` to notify admins.\n\n"
        "✅ Developed by CCU Teams of Ministry of Post and Telecommunications (MPTC)."
    )

# ------------- Incident response -------------
async def auto_mitigate(update: Update, context, user, chat_id: int, reason: str, severity: str = "medium"):
    """
    severity: 'low' -> warn; 'medium' -> delete + warn; 'high' -> delete + restrict; 'critical' -> delete + restrict longer
    """
    if severity in ("medium","high","critical"):
        await delete_message_safe(update, context)
    total = add_warning(chat_id, user.id)
    if severity == "low":
        await context.bot.send_message(chat_id, f"⚠️ {reason}. Please avoid posting risky content, @{user.username or user.first_name}.")
    elif severity == "medium":
        await context.bot.send_message(chat_id, f"🛑 {reason}. Message removed. Warning ({total}/{WARN_LIMIT}).")
    elif severity == "high":
        await context.bot.send_message(chat_id, f"🚫 {reason}. You are temporarily muted for {MUTE_SECONDS}s.")
        await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
    else:  # critical
        await context.bot.send_message(chat_id, f"⛔ {reason}. You are muted for {MUTE_SECONDS*3}s.")
        await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS*3))
    try:
        await notify_admins(context, f"🔎 Security action\n• Chat: {chat_id}\n• UID: {user.id}\n• Reason: {reason}\n• Severity: {severity}")
    except Exception:
        pass

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
        correct = random.randint(1, 4)
        options = list(range(1, 5)); random.shuffle(options)
        keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify_join:{token}:{int(n==correct)}")] for n in options]
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

    # Personalized welcome message in DM
    name = f"{update.effective_user.first_name or ''} {update.effective_user.last_name or ''}".strip() or (
        f"@{update.effective_user.username}" if update.effective_user.username else str(update.effective_user.id)
    )
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text=build_welcome_message(name),
        parse_mode="Markdown"
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

# --- Admin-only commands ---
async def cmd_ping(update: Update, context):
    if not is_admin(update.effective_user.id):
        await enforce_admin_violation(update, context, "use admin-only commands (/ping)")
        return
    await context.bot.send_message(update.effective_chat.id, "🏓 pong")

async def cmd_diagnose(update: Update, context):
    if not is_admin(update.effective_user.id):
        await enforce_admin_violation(update, context, "use admin-only commands (/diagnose)")
        return
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
        "• Instant admin alert when someone joins or requests to join\n\n"
        "**Admin Controls**\n"
        "• /addbadword <word ...> – Add banned words (admins only)\n"
        "• /removebadword <word ...> – Remove banned words (admins only)\n"
        "• /togglelinks – Enable/disable link blocking (admins only)\n"
        "• /ping – Quick connectivity test (admins only)\n"
        "• /diagnose – Show bot permissions & config (admins only)\n\n"
        "**Security Scanner**\n"
        "• Link & IP reputation checks: Google Safe Browsing, VirusTotal, AbuseIPDB\n"
        "• AI toxicity screening via Perspective API\n"
        "• Send a **file/photo** to scan with **VirusTotal**."
    )
    await context.bot.send_message(update.effective_chat.id, text, parse_mode="Markdown")

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

    # Track username (session-only)
    try:
        SESSION_USERNAMES[user.id] = user.username
    except Exception:
        pass

    if is_admin(user.id):
        return

    # Flood control
    if record_user_message(chat_id, user.id) > FLOOD_MAX_MSG:
        await delete_message_safe(update, context)
        await context.bot.send_message(chat_id, f"⌛ Slow down, @{user.username or user.first_name} (muted {MUTE_SECONDS}s).")
        await restrict_user(chat_id, user.id, context, until_date=datetime.now() + timedelta(seconds=MUTE_SECONDS))
        return

    # Toxicity AI (Perspective)
    if PERSPECTIVE_API_KEY and len(text) >= 10:
        scores = await analyze_toxicity(text)
        if scores:
            tox = scores.get("TOXICITY", 0.0)
            sev = scores.get("SEVERE_TOXICITY", 0.0)
            ins = scores.get("INSULT", 0.0)
            thr = scores.get("THREAT", 0.0)
            if tox >= TOXICITY_THRESHOLD or sev >= SEVERE_TOXICITY_THRESHOLD or ins >= INSULT_THRESHOLD or thr >= THREAT_THRESHOLD:
                reason = f"Toxic content detected (tox={tox:.2f}, severe={sev:.2f}, insult={ins:.2f}, threat={thr:.2f})"
                await auto_mitigate(update, context, user, chat_id, reason, severity="medium")
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

    # Robust URL/domain extraction (prevents bypass)
    urls = extract_urls_and_domains(text)

    # Link reputation & blocking
    if urls:
        if BLOCK_LINKS:
            await delete_message_safe(update, context)
            await context.bot.send_message(chat_id, "🔗 Links are restricted here. If it’s class‑related, ask an admin.")
            add_warning(chat_id, user.id)

        # Risk checks (only check the first normalized URL for speed; can expand)
        gsb_bad, gsb_detail = check_google_safebrowsing(urls)
        vt_bad, vt_detail = False, ""
        if urls:
            vt_bad, vt_detail = check_virustotal_url(urls[0])
        if gsb_bad or vt_bad:
            reasons = []
            if gsb_bad: reasons.append(f"[GSB] {gsb_detail}")
            if vt_bad: reasons.append(f"[VT] {vt_detail}")
            reason = " ; ".join(reasons)
            severity = "high" if ("MALWARE" in gsb_detail or vt_bad) else "medium"
            await auto_mitigate(update, context, user, chat_id, reason, severity=severity)
            return

    # IP reputation (AbuseIPDB)
    # Extract IPs from the deobfuscated text + URLs
    def extract_ips(text2: str, url_list: List[str]) -> List[str]:
        ips = []
        t2 = deobfuscate_text(text2)
        ips += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t2 or "")
        for u in url_list:
            try:
                host = urlparse(u).hostname
                if host and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
                    ips.append(host)
            except Exception:
                pass
        out = []
        for ip in ips:
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                out.append(ip)
        return list(dict.fromkeys(out))[:20]

    ips = extract_ips(text, urls)
    if ips and ABUSEIPDB_API_KEY:
        bad_hits = []
        for ip in ips[:5]:
            bad, detail, score = check_abuseipdb_ip(ip)
            if bad:
                bad_hits.append((ip, score, detail))
        if bad_hits:
            worst = max(bad_hits, key=lambda x: x[1])
            reason = f"IP reputation bad: {worst[0]} (confidence={worst[1]}) via AbuseIPDB"
            await auto_mitigate(update, context, user, chat_id, reason, severity="high")
            return

# ------------- Join alert + CAPTCHA (Post-join) -------------
async def welcome_verify(update: Update, context):
    chat_id = update.effective_chat.id
    chat_title = update.effective_chat.title or str(chat_id)
    for new_member in update.message.new_chat_members:
        logger.info(f"NEW_CHAT_MEMBER: {new_member.id} joined chat {chat_id}")
        UNVERIFIED.add((chat_id, new_member.id))
        await restrict_user(chat_id, new_member.id, context, until_date=None)
        correct = random.randint(1, 4)
        options = list(range(1, 5)); random.shuffle(options)
        keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify:{new_member.id}:{int(n==correct)}")] for n in options]
        PENDING_CAPTCHA[new_member.id] = {"chat_id": chat_id, "answer": correct, "mode": "post", "token": None}
        uid = new_member.id
        isbot = "true" if new_member.is_bot else "false"
        fn = new_member.first_name or "-"
        ln = new_member.last_name or "-"
        username_line = username_change_alert(uid, new_member.username)
        link = f"(https://t.me/{new_member.username})" if new_member.username else "(-)"
        lang = getattr(new_member, "language_code", None) or "-"
        alert_group = (
            "📣 NEW MEMBER ALERT\n"
            f"• Group: {chat_title} ({chat_id})\n"
            f"• UID: {uid}\n• is_bot: {isbot}\n• first_name: {fn}\n• last_name: {ln}\n"
            f"{username_line} {link}\n• language_code: {lang}\n\n"
            f"Please verify: pick **{correct}** to unlock chatting.\nUID: `{new_member.id}`"
        )
        await context.bot.send_message(chat_id, alert_group, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

        # Post the custom welcome message for new member (with name)
        name = f"{new_member.first_name or ''} {new_member.last_name or ''}".strip() or (
            f"@{new_member.username}" if new_member.username else str(new_member.id)
        )
        await context.bot.send_message(chat_id, build_welcome_message(name), parse_mode="Markdown")

        alert_admin = (
            "🔔 NEW MEMBER JOINED\n"
            f"• Group: {chat_title} ({chat_id})\n"
            f"• UID: {uid}\n"
            f"{username_line}\n"
            f"• Name: {fn} {ln}\n"
            "A post‑join CAPTCHA has been posted and the user is currently restricted."
        )
        await notify_admins(context, alert_admin)

# ------------- Join Request (Pre-join verification) -------------
async def handle_join_request(update: Update, context):
    req = update.chat_join_request
    chat_id = req.chat.id
    chat_title = req.chat.title or str(chat_id)
    user = req.from_user
    token = gen_token()
    PENDING_JOIN[token] = {"chat_id": chat_id, "user_id": user.id}
    deep_link = f"https://t.me/{BOT_USERNAME}?start=join-{token}" if BOT_USERNAME else None
    UNVERIFIED.add((chat_id, user.id))
    logger.info(f"JOIN REQUEST: stored token {token} for {(chat_id, user.id)}")
    dm_text = (
        "👋 You requested to join the group.\n"
        "Please complete the CAPTCHA to get approved.\n\n"
        f"➡️ Tap this link to start verification: {deep_link or 'Open the bot and send /start join-' + token}"
    )
    try:
        await context.bot.send_message(user.id, dm_text)
    except Exception as e:
        logger.debug(f"DM to user failed (likely user never started bot): {e}")

    SESSION_USERNAMES[user.id] = user.username
    username_line = username_change_alert(user.id, user.username)
    admin_text = (
        "🔔 NEW JOIN REQUEST\n"
        f"• Group: {chat_title} ({chat_id})\n"
        f"• UID: {user.id}\n"
        f"{username_line}\n"
        f"• Name: {user.first_name or '-'} {user.last_name or '-'}\n\n"
        "Pre‑join verification required. If the user cannot receive DMs, ask them to start the bot and click:\n"
        f"{deep_link or '(bot username not yet known; user should open the bot and send /start join-' + token + ')'}"
    )
    await notify_admins(context, admin_text)

# ------------- VirusTotal file scanning (updated output with configurable Top 3 engines) -------------
def _normalize(s: str) -> str:
    return re.sub(r"[\s_\-]+", "", (s or "")).lower()

def _pick_engine_result(results: dict, target_engine: str) -> Tuple[str, Optional[str]]:
    """
    Find the best matching engine name in VirusTotal 'results' for target_engine.
    Returns (category, result) where category ∈ {malicious, suspicious, harmless, undetected, ...},
    result is the signature string or None.
    If engine is not found, returns ('undetected', None) treating it as Clean.
    """
    if not results:
        return ("undetected", None)
    tnorm = _normalize(target_engine)
    best_key = None
    # Prefer exact (normalized) match, else substring match
    for k in results.keys():
        knorm = _normalize(k)
        if knorm == tnorm:
            best_key = k
            break
    if best_key is None:
        for k in results.keys():
            knorm = _normalize(k)
            if tnorm in knorm or knorm in tnorm:
                best_key = k
                break
    if best_key is None:
        return ("undetected", None)
    det = results.get(best_key, {}) or {}
    category = det.get("category") or "undetected"
    result = det.get("result")
    return (category, result)

def _format_engine_line(rank: int, engine_name: str, category: str, result: Optional[str]) -> str:
    """
    Returns human-friendly line: '- Top N: <engine> – Clean/Detected'
    """
    detected = (category in ("malicious", "suspicious"))
    status = f"Detected ({result})" if detected and result else ("Detected" if detected else "Clean")
    return f"- Top {rank}: {engine_name} – {status}"

async def vt_scan_and_report(file_path: str, progress_msg, display_name: str):
    """
    Uploads the file to VirusTotal, waits for analysis completion, then reports:
    - File name
    - Summary (Malicious, Suspicious, Undetected X/Total)
    - Virus Engines (Top 1–Top 3): Clean or Detected (signature)
    """
    if requests is None:
        await progress_msg.edit_text("❌ 'requests' not installed. Add it to requirements.txt and redeploy."); return
    if not VT_API_KEY:
        await progress_msg.edit_text("❌ VirusTotal API key (VT_API_KEY) not configured."); return

    # Upload
    try:
        with open(file_path, "rb") as f:
            resp = requests.post(f"{VT_BASE}/files", headers={"x-apikey": VT_API_KEY}, files={"file": f})
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id")
        if not analysis_id:
            await progress_msg.edit_text("❌ Failed to get analysis ID from VirusTotal."); return
        await progress_msg.edit_text("✅ File uploaded! Scanning in progress...")
    except Exception as e:
        await progress_msg.edit_text(f"❌ Upload error: {escape_markdown(str(e), version=2)}", parse_mode="MarkdownV2"); return

    # Poll for completion and build compact report
    idx, prev, attempts, max_attempts = 0, None, 0, 120
    headers = {"x-apikey": VT_API_KEY}
    while attempts < max_attempts:
        await asyncio.sleep(5)
        try:
            s = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers)
            s.raise_for_status()
            attrs = s.json().get("data", {}).get("attributes", {})
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {}) or {}
                results = attrs.get("results", {}) or {}

                total_engines = len(results) if results else (
                    int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0)) +
                    int(stats.get("undetected", 0)) + int(stats.get("harmless", 0))
                )
                undetected = int(stats.get("undetected", 0))

                # Build Top 1–Top 3 engine lines
                chosen = TOP_ENGINES[:3]
                lines = []
                for i, eng in enumerate(chosen, start=1):
                    cat, res = _pick_engine_result(results, eng)
                    lines.append(_format_engine_line(i, eng, cat, res))
                engines_block = "\n".join(lines)

                summary = (
                    f"✅ **Scan Complete!**\n\n"
                    f"📄 **File:** `{escape_markdown(display_name, version=2)}`\n"
                    f"🔎 **Summary:**\n"
                    f"• 🛡 **Malicious:** `{stats.get('malicious', 0)}`\n"
                    f"• ⚠️ **Suspicious:** `{stats.get('suspicious', 0)}`\n"
                    f"• ❓ **Undetected:** `{undetected}/{total_engines}`\n\n"
                    f"🧪 **Virus Engines:**\n"
                    f"{escape_markdown(engines_block, version=2)}\n\n"
                    f"Powered by CCU Teams of MPTC"
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
    display_name = doc.file_name or os.path.basename(path)
    progress = await context.bot.send_message(update.effective_chat.id, "⏳ Uploading file to VirusTotal and starting scan...")
    await vt_scan_and_report(path, progress, display_name)

async def scan_photo(update: Update, context):
    photo = update.message.photo[-1]
    file = await photo.get_file()
    path = await file.download_to_drive()
    display_name = os.path.basename(path)  # Telegram provides a generated name; use basename
    progress = await context.bot.send_message(update.effective_chat.id, "⏳ Uploading image to VirusTotal and starting scan...")
    await vt_scan_and_report(path, progress, display_name)

# ------------- Verify button (both modes) -------------
async def verify_callback(update: Update, context):
    q = update.callback_query; await q.answer()
    try:
        if q.data.startswith("verify:"):
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
                name = f"{q.from_user.first_name or ''} {q.from_user.last_name or ''}".strip() or (f"@{q.from_user.username}" if q.from_user.username else str(q.from_user.id))
                await q.edit_message_text(f"✅ Verified. Welcome {name}")
                PENDING_CAPTCHA.pop(user_id, None)
            else:
                await q.edit_message_text("❌ Wrong answer. Try again.")
        elif q.data.startswith("verify_join:"):
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
                name = f"{q.from_user.first_name or ''} {q.from_user.last_name or ''}".strip() or (f"@{q.from_user.username}" if q.from_user.username else str(q.from_user.id))
                await q.edit_message_text(f"✅ Verified. Welcome {name}")
                PENDING_JOIN.pop(token, None)
                PENDING_CAPTCHA.pop(user_id, None)
            else:
                correct = PENDING_CAPTCHA.get(user_id, {}).get("answer", random.randint(1, 4))
                options = list(range(1, 5)); random.shuffle(options)
                keyboard = [[InlineKeyboardButton(str(n), callback_data=f"verify_join:{token}:{int(n==correct)}")] for n in options]
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
    .updater(None)
    .defaults(Defaults(block=False))
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

# ---- Handlers ----
application.add_handler(MessageHandler(filters.ALL, log_all_updates), group=-1)

group_chats_filter_v20 = (filters.ChatType.GROUP | filters.ChatType.SUPERGROUP)

application.add_handler(MessageHandler(group_chats_filter_v20 & filters.ALL, gate_unverified, block=False), group=0)

application.add_handler(CommandHandler("start", cmd_start, block=False), group=1)
application.add_handler(CommandHandler("rules", cmd_rules, block=False), group=1)
application.add_handler(CommandHandler("report", cmd_report, block=False), group=1)
application.add_handler(CommandHandler("warnings", cmd_warnings, block=False), group=1)
application.add_handler(CommandHandler("function", cmd_function, block=False), group=1)

# Admin-only commands
application.add_handler(CommandHandler("ping", cmd_ping, block=False), group=1)
application.add_handler(CommandHandler("diagnose", cmd_diagnose, block=False), group=1)

application.add_handler(MessageHandler(filters.Document.ALL, scan_document, block=False), group=1)
application.add_handler(MessageHandler(filters.PHOTO, scan_photo, block=False), group=1)

# Post-join & pre-join
application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, welcome_verify), group=1)
application.add_handler(ChatJoinRequestHandler(handle_join_request), group=1)

# Unified verification callback
application.add_handler(CallbackQueryHandler(verify_callback, pattern=r"^(verify:|verify_join:)"), group=1)

# Moderation
application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, moderate), group=1)

# ---- Command tap (optional log) ----
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

# ---- Commands menu ----
async def set_my_commands():
    try:
        cmds = [
            BotCommand("start","Introduction"),
            BotCommand("rules","Show group rules"),
            BotCommand("report","Report an issue to admins"),
            BotCommand("warnings","Show your warnings"),
            BotCommand("function","Show all bot functions"),
            BotCommand("ping","Quick connectivity test (admins only)"),
            BotCommand("diagnose","Show bot permissions & config (admins only)"),
        ]
        await application.bot.set_my_commands(cmds)
    except Exception as e:
        logger.debug(f"set_my_commands failed: {e}")

# ---- Starlette app & webhook ----
async def healthz(request: Request): return JSONResponse({"status":"ok"})
async def root(request: Request): return PlainTextResponse("OK", status_code=200)

async def webhook(request: Request) -> Response:
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

# ---- Async main ----
async def main():
    import uvicorn
    port = int(os.getenv("PORT", "10000"))
    logger.info(f"Starting Uvicorn on 0.0.0.0:{port}")
    config = uvicorn.Config(app=app, host="0.0.0.0", port=port, workers=1, log_level="info")
    server = uvicorn.Server(config)
    await application.initialize()
    await application.start()
    global BOT_USERNAME
    try:
        me = await application.bot.get_me()
        BOT_USERNAME = me.username
        logger.info(f"BOT_USERNAME resolved: {BOT_USERNAME}")
    except Exception as e:
        logger.warning(f"Failed to resolve BOT_USERNAME: {e}")
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
    await server.serve()
    await application.stop()
    await application.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
