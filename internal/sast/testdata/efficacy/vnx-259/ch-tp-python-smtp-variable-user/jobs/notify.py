import smtplib
from ftplib import FTP_TLS

SENDER = "alerts@example.com"


def send(msg):
    with smtplib.SMTP_SSL("smtp.example.com", 465) as server:
~>        server.login(SENDER, "Al3rtsMa1l!")
        server.send_message(msg)


def upload(path):
    ftp = FTP_TLS("files.example.com")
~>    ftp.login(os_user(), "Depl0y-Ftp-9")
