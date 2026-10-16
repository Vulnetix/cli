import os


def take_db_password() -> str:
    password = os.environ.get("DB_PASSWORD")
    if password is None:
        password = os.environ["DB_PASSWORD_FALLBACK"]
    os.environ.pop("DB_PASSWORD", None)
    del os.environ["DB_PASSWORD_FALLBACK"]
    os.unsetenv("API_TOKEN")
    return password
