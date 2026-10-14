import sendgrid
from sendgrid.helpers.mail import Mail

~>sg = sendgrid.SendGridAPIClient(api_key='@@sample:SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}@@')


def send_receipt(to_addr, body):
    message = Mail(from_email="billing@shop.invalid", to_emails=to_addr,
                   subject="Your receipt", html_content=body)
    return sg.send(message)
