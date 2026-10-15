import re

GITLAB_PAT = re.compile(r"glpat-[0-9A-Za-z_\-]{20,}")
PREFIXES = ("glpat-", "gldt-", "glrt-", "glcbt-", "gloas-", "glptt-")


def is_gitlab(token: str) -> bool:
    return token.startswith(PREFIXES)
