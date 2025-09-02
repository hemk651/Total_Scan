import os
import logging
import requests
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters

# Logging setup
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(_name_)

# Environment variables
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "32"))
DELETE_BAD = os.getenv("DELETE_BAD", "1") == "1"

VT_API_URL = "https://www.virustotal.com/api/v3/files"

async def scan_file(file_path: str):
    """Upload file to VirusTotal and fetch result."""
    headers = {"x-apikey": VT_API_KEY}
    files = {"file": open(file_path, "rb")}

    try:
        response = requests.post(VT_API_URL, headers=headers, files=files)
        files["file"].close()

        if response.status_code != 200:
            return {"error": f"VirusTotal API Error: {response.status_code}"}

        data_id = response.json()["data"]["id"]
        result_url = f"{VT_API_URL}/{data_id}"

        # Poll until scan completes
        while True:
            res = requests.get(result_url, headers=headers)
            result = res.json()
            status = result["data"]["attributes"]["status"]
            if status == "completed":
                return result
    except Exception as e:
        return {"error": str(e)}

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle uploaded files and scan them."""
    try:
        file = await update.message.document.get_file()
        file_size = update.message.document.file_size / (1024 * 1024)

        if file_size > MAX_FILE_MB:
            await update.message.reply_text(f"⚠ File too large! Max: {MAX_FILE_MB}MB")
            return

        file_path = f"/tmp/{update.message.document.file_name}"
        await file.download_to_drive(file_path)

        await update.message.reply_text("🔍 Scanning your file via VirusTotal...")
        result = await scan_file(file_path)

        if "error" in result:
            await update.message.reply_text(f"❌ Error: {result['error']}")
            os.remove(file_path)
            return

        stats = result["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]

        if malicious > 0:
            await update.message.reply_text(f"🚨 {malicious} threats detected!")
            if DELETE_BAD:
                try:
                    await update.message.delete()
                except Exception:
                    pass
        else:
            await update.message.reply_text("✅ File is clean and safe.")

        os.remove(file_path)
    except Exception as e:
        logger.error(f"Error in handle_file: {e}")
        await update.message.reply_text("⚠ Unexpected error while scanning.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🤖 Send me any file, I'll scan it using VirusTotal.")

def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(MessageHandler(filters.TEXT & filters.Regex("^/start$"), start))
    logger.info("Bot started successfully.")
    app.run_polling()

if _name_ == "_main_":
    main()