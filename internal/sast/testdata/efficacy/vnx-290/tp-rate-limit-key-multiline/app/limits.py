from flask import request
from flask_limiter import Limiter

~>limiter = Limiter(key_func=lambda: request.headers.get("X-Real-IP") or request.remote_addr)
