import smtplib


def send(message):
    # old relay, replaced by the API client below
~>    # server = smtplib.SMTP("smtp.legacy-relay.net", 587)
    # server.login("alerts", "relay-pass-2019")
    # server.sendmail("alerts@acme.io", message.to, message.body)
    # server.quit()
    return api_client.send(message)
