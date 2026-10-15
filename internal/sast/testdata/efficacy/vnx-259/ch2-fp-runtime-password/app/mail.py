import os
import imaplib


def fetch(cfg):
    box = imaplib.IMAP4_SSL("imap.example.com")
    box.login("reports@example.com", os.environ["IMAP_PASSWORD"])
    box.login(cfg.user, cfg.password)
    box.login("reports@example.com", getpass.getpass("Password: "))
    return box
