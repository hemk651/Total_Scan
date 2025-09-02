import os
import logging
import aiohttp
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(_name_)

# Load environment variables
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", 32))  # Default: 32MB
DELETE_BAD = os.getenv("DELETE_BAD", "1") == "1"

# VirusTotal API URL
VT_URL = "https://www.virustotal.com/api/v3/files"

# Scan uploaded documents
async def scan_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.document:
        return

    file_info = await context.bot.get_file(update.message.document.file_id)

    # Check file size
    file_size = update.message.document.file_size / (1024 * 1024)
    if file_size > MAX_FILE_MB:
        await update.message.reply_text(
            f"⚠ File too large! Max size is {MAX_FILE_MB}MB."
        )
        return

    # Download file
    file_path = f"temp_{update.message.document.file_name}"
    await file_info.download_to_drive(file_path)

    try:
        # Upload file to VirusTotal
        async with aiohttp.ClientSession() as session:
            headers = {"x-apikey": VT_API_KEY}
            with open(file_path, "rb") as f:
                data = aiohttp.FormData()
                data.add_field("file", f, filename=update.message.document.file_name)
                async with session.post(VT_URL, headers=headers, data=data) as response:
                    vt_result = await response.json()

        # Parse result
        analysis_id = vt_result.get("data", {}).get("id")
        if not analysis_id:
            await update.message.reply_text("❌ Error scanning file.")
            return

        # Fetch analysis report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        async with aiohttp.ClientSession() as session:
            headers = {"x-apikey": VT_API_KEY}
            async with session.get(report_url, headers=headers) as response:
                report = await response.json()

        stats = report.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        # Send scan result
        if malicious > 0 or suspicious > 0:
            msg = f"🚨 Threats Detected!\nMalicious: {malicious}\nSuspicious: {suspicious}"
            await update.message.reply_markdown(msg)

            # Optionally delete infected files
            if DELETE_BAD:
                await update.message.delete()
        else:
            await update.message.reply_text("✅ File is safe.")

    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        await update.message.reply_text("⚠ An error occurred while scanning.")
    finally:
        # Remove temporary file
        if os.path.exists(file_path):
            os.remove(file_path)

# Main function to start bot
def main():
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.Document.ALL, scan_document))
    app.run_polling()

if _name_ == "_main_":
    main()