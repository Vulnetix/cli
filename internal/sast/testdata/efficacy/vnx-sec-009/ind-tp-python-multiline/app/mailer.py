import sendgrid
from sendgrid.helpers.mail import Mail


def build_client():
    return sendgrid.SendGridAPIClient(
~>        api_key="@@sample:SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}@@"
    )


def send_receipt(order):
    msg = Mail(
        from_email="billing@shop.example",
        to_emails=order.email,
        subject="Receipt " + order.id,
        html_content="<p>Thanks</p>",
    )
    return build_client().send(msg)
