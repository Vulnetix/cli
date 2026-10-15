import base64


def export(settings):
    secret = settings.SMTP_PASSWORD
~>    blob = base64.b64encode(secret.encode())
    return {"smtp": blob.decode()}


def export_many(conf):
~>    return {k: base64.b64encode(v.encode()) for k, v in [("db", conf.db_password)]}
