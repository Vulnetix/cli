import os

API_TOKEN = os.environ["API_TOKEN"]
db_password = os.environ.get("DB_PASSWORD", "")
os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
del os.environ["GITHUB_TOKEN"]
if "SECRET_KEY" in os.environ:
    print("secret configured")
os.environ["SECRET_KEY"] = os.environ.get("DJANGO_SECRET_KEY", "")
