import os
import hashlib
import asyncio
import httpx
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, MessageHandler, CommandHandler, ContextTypes, filters

# Load environment variables
load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "32"))
DELETE_BAD = os.getenv("DELETE_BAD", "0") == "1"

# Calculate SHA256 hash
def get_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# Lookup hash in VirusTotal
async def vt_lookup_hash(sha256):
    async with httpx.AsyncClient() as client:
        r = await client.get(f"{VT_URL}/files/{sha256}", headers=HEADERS)
        return r.json() if r.status_code == 200 else None

# Upload file to VirusTotal
async def vt_upload_file(file_path):
    async with httpx.AsyncClient(timeout=120) as client:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            r = await client.post(f"{VT_URL}/files", headers=HEADERS, files=files)
            return r.json()

# Format VirusTotal report
def format_report(data):
    stats = data["data"]["attributes"]["last_analysis_stats"]
    malicious = stats["malicious"]
    total = sum(stats.values())
    link = f"https://www.virustotal.com/gui/file/{data['data']['id']}"
    return f"🔍 *VirusTotal Scan Result*\n\nMalicious: {malicious}/{total}\n[View Report]({link})"

# Handle incoming files
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    if not document:
        return

    file = await document.get_file()
    file_path = f"/tmp/{file.file_unique_id}_{file.file_path.split('/')[-1]}"
    await file.download_to_drive(file_path)

    # Check file size
    if os.path.getsize(file_path) > MAX_FILE_MB * 1024 * 1024:
        await update.message.reply_text("⚠ File too large for VirusTotal free API (32MB limit).")
        os.remove(file_path)
        return

    # First try hash lookup
    sha256 = get_sha256(file_path)
    report = await vt_lookup_hash(sha256)

    # If unknown, upload to VirusTotal
    if not report:
        await update.message.reply_text("⏳ Uploading file to VirusTotal for analysis...")
        report = await vt_upload_file(file_path)

    # Send formatted report
    message = format_report(report)
    await update.message.reply_markdown(message)

    # Delete malicious files if enabled
    malicious_count = report["data"]["attributes"]["last_analysis_stats"]["malicious"]
    if DELETE_BAD and malicious_count > 0:
        await update.message.delete()

    os.remove(file_path)

# Start command
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🤖 Bot is online! Send a file to scan.")

# Main function
def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.run_polling()

if _name_ == "_main_":
    main()