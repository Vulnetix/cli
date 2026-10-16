from slack_sdk import WebClient
~>client = WebClient(token="@@sample:xoxb-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}@@")
client.chat_postMessage(channel="#ops", text="up")
