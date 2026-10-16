from os import environ

from app.config import load_settings


def export_vendor_settings(settings_path: str) -> None:
    settings = load_settings(settings_path)
    api_key = settings.vendor.api_key
    client_secret = settings.oauth.client_secret

~>    environ.update({"VENDOR_API_KEY": api_key})
~>    environ.update(OAUTH_CLIENT_SECRET=client_secret)
    environ.update({"VENDOR_REGION": settings.vendor.region})


def export_named(var_name: str, api_token: str) -> None:
~>    environ[var_name] = api_token
