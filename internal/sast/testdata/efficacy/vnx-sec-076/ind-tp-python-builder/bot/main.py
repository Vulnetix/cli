from telegram.ext import ApplicationBuilder

~>TOKEN = "@@sample:[0-9]{9}:AA[A-Za-z0-9_-]{33}@@"
app = ApplicationBuilder().token(TOKEN).build()
