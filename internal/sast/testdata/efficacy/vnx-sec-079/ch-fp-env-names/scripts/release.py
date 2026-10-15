import os

github_pat_token = os.environ["GITHUB_PAT_TOKEN"]
github_pat_expiry_days = 30
TOKEN_RE = r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"
