import html


def save_comment(body):
    if "<script" in body:
        log_suspicious(body)
    safe = html.escape(body)
    store(safe)
