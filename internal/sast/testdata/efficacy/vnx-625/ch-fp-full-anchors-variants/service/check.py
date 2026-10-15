import re

ALLOWED = re.compile(r"^https://(?:[a-z0-9-]+\.)?example\.com(?::\d+)?(?:/.*)?$")


def ok_origin(origin):
    return re.fullmatch(r"https://([a-z]+\.)?example\.com", origin) is not None


def ok_host(host):
    return re.match(r"^(?:[a-z0-9-]+\.)*example\.net\Z", host) is not None


def version_ok(v):
    return re.match(r"^v\d+\.\d+\.\d+$", v) is not None


def is_app_bundle(name):
    return re.search(r"^[\w-]+\.app$", name) is not None


def is_local_settings(name):
    return re.search(r"settings\.local$", name) is not None


def is_tracker(host):
    return re.search(r"(?:^|\.)tracker\.example\.com$", host) is not None
