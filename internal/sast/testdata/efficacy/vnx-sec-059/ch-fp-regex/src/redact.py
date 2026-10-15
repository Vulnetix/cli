import re

LINEAR_KEY = re.compile(r"lin_api_[A-Za-z0-9]{40}")
LINEAR_OAUTH = re.compile(r"lin_oauth_[a-f0-9]{64}")
