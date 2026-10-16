from twilio.rest import Client

ACCOUNT_SID = "AC0123456789abcdef0123456789abcdef"
~>API_KEY_SID = "SK@@sample:[a-f0-9]{32}@@"
API_KEY_SECRET = os.environ["TWILIO_API_SECRET"]

client = Client(API_KEY_SID, API_KEY_SECRET, ACCOUNT_SID)
