import smtplib
import ssl


def legacy_context():
~>    ctx = ssl.SSLContext(@@sample:s[s]l[.][P]RO[T]OC[O]L[_][T]LS[v]1[_][1]@@)
    return ctx


def relaxed_context():
    ctx = ssl.create_default_context()
~>    ctx.minimum_version = @@sample:s[s]l[.][T]LS[V]er[s]io[n][.]T[L]Sv[1]@@
~>    ctx.set_ciphers("ECDHE+AESGCM:RC4-SHA")
    return ctx


def send(host, msg):
    with smtplib.SMTP_SSL(host, 465, context=legacy_context()) as smtp:
        smtp.send_message(msg)
