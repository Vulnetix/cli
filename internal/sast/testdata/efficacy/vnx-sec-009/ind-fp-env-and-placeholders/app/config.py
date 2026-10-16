import os

import sendgrid

# Keys look like SG.<22 chars>.<43 chars>; never commit one.
API_KEY = os.environ["SENDGRID_API_KEY"]
EXAMPLE = "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
OTHER = "SG.your-sendgrid-api-key-goes-here"

client = sendgrid.SendGridAPIClient(api_key=os.getenv("SENDGRID_API_KEY"))
