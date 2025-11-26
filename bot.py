
import os
import re
import random
from datetime import datetime, timedelta

from telegram import Update, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, CallbackQueryHandler,
    ChatMemberHandler, filters, AIORateLimiter
)

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

# ----------------------------
# Environment & Config
# ----------------------------
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_IDS = {int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip().isdigit()}
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "change-me")  # verify incoming webhook requests
BASE_URL = os.getenv("RENDER_EXTERNAL_URL", "").rstrip("/")  # set by Render
WEBHOOK_PATH = "/webhook"
WEBHOOK_URL = f"{BASE_URL}{WEBHOOK_PATH}" if BASE_URL else ""

# Safeguard policies (customize)
BAD_WORDS = {"idiot", "stupid", "fool"}
BLOCK_LINKS = True
WARN_LIMIT = 2
FLOOD_MAX_MSG = 5
FLOOD_WINDOW_SEC = 10
MUTE_SECONDS = 60

# In-memory state
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
    except Exception:
        pass

async def mute_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE, seconds: int = MUTE_SECONDS):
    # Requires bot admin rights with "Restrict Members". 
    perms = ChatPermissions(can_send_messages=False, can_send_media_messages=False,
                            can_send_polls=False, can_add_web_page_previews=False)
    until_date = datetime.now() + timedelta(seconds=seconds)
    await context.bot.restrict_chat_member(chat_id, user_id, permissions=perms, until_date=until_date)

async def unmute_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE):
    perms = ChatPermissions(can_send_messages=True, can_send_media_messages=True,
                            can_send_polls=True, can_add_web_page_previews=True)
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

# ----------------------------
# Commands
# ----------------------------
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Hello! I keep this group safe—moderation, anti-spam, and new member verification.\n"
        "Use /rules to see the code of conduct, or /report to alert admins."
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
            await context.bot.send_message(admin_id,
                f"[REPORT] Chat {update.effective_chat.id} from @{update.effective_user.username or update.effective_user.id}: {reason}")
        except Exception:
            pass

async def cmd_warnings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    count = USER_WARNINGS.get((update.effective_chat.id, update.effective_user.id), 0)
    await update.message.reply_text(f"Your current warnings: {count}")

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
# New member verification (CAPTCHA)
# ----------------------------
async def welcome_verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    for new_member in update.message.new_chat_members:
        # initial restriction
        await mute_user(chat_id, new_member.id, context, seconds=MUTE_SECONDS)
        correct = random.randint(1, 4)
        options = list(range(1, 5))
        random.shuffle(options)
        keyboard = [
            [InlineKeyboardButton(str(n), callback_data=f"verify:{new_member.id}:{int(n==correct)}")]
            for n in options
        ]
        PENDING_CAPTCHA[new_member.id] = {"chat_id": chat_id, "answer": correct}
        await context.bot.send_message(
            chat_id,
            f"👋 Welcome, @{new_member.username or new_member.first_name}!\n"
            f"Please verify: pick **{correct}** to unlock chatting.",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )

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
    except Exception:
        pass

# ----------------------------
# Build PTB Application (async + rate limiter)
# ----------------------------
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is missing. Set it in environment.")
application = (
    ApplicationBuilder()
    .token(BOT_TOKEN)
    .rate_limiter(AIORateLimiter())  # avoid flood limits
    .build()
)

# Handlers
application.add_handler(CommandHandler("start", cmd_start))
application.add_handler(CommandHandler("rules", cmd_rules))
application.add_handler(CommandHandler("report", cmd_report))
application.add_handler(CommandHandler("warnings", cmd_warnings))
application.add_handler(CommandHandler("addbadword", addbadword))
application.add_handler(CommandHandler("removebadword", removebadword))
application.add_handler(CommandHandler("togglelinks", togglelinks))
application.add_handler(MessageHandler((filters.TEXT | filters.CAPTION) & ~filters.COMMAND, moderate))
application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, welcome_verify))
application.add_handler(CallbackQueryHandler(verify_callback, pattern=r"^verify:"))
application.add_handler(ChatMemberHandler(lambda *_: None))  # optional

# ----------------------------
# Starlette Web App (webhook + health check)
# ----------------------------
async def healthz(request: Request):
    return JSONResponse({"status": "ok"})

async def root(request: Request):
    return PlainTextResponse("OK", status_code=200)

async def webhook(request: Request):
    # Verify secret token header from Telegram when set_webhook(..., secret_token=WEBHOOK_SECRET)
    if WEBHOOK_SECRET:
        hdr = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if hdr != WEBHOOK_SECRET:
            return PlainTextResponse("forbidden", status_code=403)

    data = await request.json()
    update = Update.de_json(data, application.bot)
    await application.process_update(update)
    return PlainTextResponse("ok")

routes = [
    Route("/", root, methods=["GET"]),
    Route("/healthz", healthz, methods=["GET"]),
    Route(WEBHOOK_PATH.lstrip("/"), webhook, methods=["POST"]),
]
app = Starlette(routes=routes)

# Startup/Shutdown: PTB lifecycle + webhook registration
@app.on_event("startup")
async def on_startup():
    await application.initialize()
    await application.start()
    if WEBHOOK_URL:
        await application.bot.set_webhook(url=WEBHOOK_URL, secret_token=WEBHOOK_SECRET)

@app.on_event("shutdown")
async def on_shutdown():
    await application.stop()

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "10000"))  # Render sets PORT automatically
    uvicorn.run("bot:app", host="0.0.0.0", port=port, workers=1)
