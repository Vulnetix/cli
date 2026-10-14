import os
from twilio.rest import Client

client = Client(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"])
auth_token = os.getenv("TWILIO_AUTH_TOKEN")
