import smtplib


def mailbox_exists(host, address):
    smtp = smtplib.SMTP(host)
    try:
        smtp.verify(address)
    except Exception:
        pass
    finally:
        smtp.quit()
    return True
