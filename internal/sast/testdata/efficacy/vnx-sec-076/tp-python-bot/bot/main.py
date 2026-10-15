from telegram.ext import ApplicationBuilder

~>TOKEN = "@@sample:[0-9]{10}@@:AA@@sample:[A-Za-z0-9_-]{33}@@"
app = ApplicationBuilder().token(TOKEN).build()
