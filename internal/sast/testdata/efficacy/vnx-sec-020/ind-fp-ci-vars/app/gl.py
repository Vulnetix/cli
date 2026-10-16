import os, re, gitlab

gl = gitlab.Gitlab("https://gitlab.com", private_token=os.environ["GITLAB_TOKEN"])
PAT_RE = re.compile(r"^glpat-[A-Za-z0-9_-]{20}$")

def is_pat(t):
    return t.startswith("glpat-")
