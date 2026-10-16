import discord

client = discord.Client(intents=discord.Intents.default())
~>TOKEN = "MTEyMjMzNDQ1NTY2Nzc4ODk5.@@sample:[A-Za-z0-9_-]{6}@@.@@sample:[A-Za-z0-9_-]{27}@@"
client.run(TOKEN)
