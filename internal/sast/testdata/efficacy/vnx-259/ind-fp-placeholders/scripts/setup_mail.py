import smtplib


def check(host, user):
    server = smtplib.SMTP(host, 587)
    server.login(user, "")
    server.login(user, "your-password")
    server.login(user, "${SMTP_PASSWORD}")
    server.login(user, "<password>")
    server.login(user, "********")
    print('example usage: server.login("me@example.org", "Tr0ub4dor-3")')
