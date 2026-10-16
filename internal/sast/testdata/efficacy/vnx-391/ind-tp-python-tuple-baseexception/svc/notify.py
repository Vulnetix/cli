import smtplib


def send_receipt(smtp_host, sender, recipient, body):
    try:
        with smtplib.SMTP(smtp_host, 587) as s:
            s.starttls()
            s.sendmail(sender, [recipient], body)
~>    except (smtplib.SMTPException, BaseException):
        pass
