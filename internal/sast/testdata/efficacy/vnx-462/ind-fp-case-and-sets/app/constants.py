HEADER_ALIASES = {
    "Content-Type": "content_type",
    "content-type": "content_type",
    "ETag": "etag",
    "Etag": "etag",
}

ALLOWED_METHODS = {"GET", "HEAD", "GET"}

defaults = dict(timeout=10, retries=3)
defaults.update({"timeout": 30})
defaults.update({"timeout": 60})
