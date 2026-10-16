from fastapi import Header
import settings


def reindex(x_admin_token: str = Header(...)):
~>    assert x_admin_token == settings.ADMIN_TOKEN
    return "ok"
