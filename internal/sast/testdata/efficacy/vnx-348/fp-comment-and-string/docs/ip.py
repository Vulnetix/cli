# Do not write: request.headers.get("X-Forwarded-For") or request.remote_addr
HELP = "X-Forwarded-For is client controlled; prefer REMOTE_ADDR"
