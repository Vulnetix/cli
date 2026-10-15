import os

DATABASE_URL = f"postgresql://postgres:{os.environ['PGPASSWORD']}@db:5432/app"
REDIS_URL = "redis://redis:6379/0"
UPSTREAM = "https://github.com/admin/admin"
ADMIN_PANEL = "https://admin.example.com:8443/login"
