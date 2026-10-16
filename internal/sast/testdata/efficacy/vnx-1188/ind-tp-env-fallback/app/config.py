import os

DB_URL = os.environ.get("DB_URL")
~>VERIFY_SSL = os.environ.get("VERIFY_SSL", "false")
~>REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "0")
PORT = os.environ.get("PORT", "8080")
