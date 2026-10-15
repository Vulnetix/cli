import os

# os.environ["DB_PASSWORD"] = password
os.environ["DB_PASSWORD"] = ""
os.environ["SECRET_KEY_FILE"] = "/run/secrets/key"
note = 'os.environ["API_TOKEN"] = token'
