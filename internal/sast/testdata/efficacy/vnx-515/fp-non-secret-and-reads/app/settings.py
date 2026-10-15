import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")
os.environ["TZ"] = "UTC"
os.environ["PATH"] = os.environ["PATH"] + ":/opt/bin"
token = os.environ["API_TOKEN"]
SECRET_KEY = os.environ.get("SECRET_KEY")
os.environ["GITHUB_TOKEN"] = os.environ.get("GH_TOKEN", "")
del os.environ["AWS_SECRET_ACCESS_KEY"]
os.environ.pop("DB_PASSWORD", None)
os.environ["TEMP"] = tempdir
