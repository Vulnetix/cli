from twilio.rest import Client

TWILIO_ACCOUNT_SID = os.environ["TWILIO_ACCOUNT_SID"]
~>TWILIO_AUTH_TOKEN = "@@sample:[0-9a-f]{32}@@"

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
