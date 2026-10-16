from twilio.rest import Client

ACCOUNT_SID = "AC@@sample:[a-f0-9]{32}@@"
~>API_KEY_SID = "SK@@sample:[a-f0-9]{32}@@"
API_KEY_SECRET = os.environ["TWILIO_API_SECRET"]

client = Client(API_KEY_SID, API_KEY_SECRET, ACCOUNT_SID)
