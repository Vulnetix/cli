import imaplib
import pymysql


def fetch():
    box = imaplib.IMAP4_SSL("imap.example.com")
~>    box.login("reports@example.com", "Spr1ngT1me!")
~>    conn = pymysql.connect("db.internal", "app", "Wint3rIsC0ming")
    return box, conn
