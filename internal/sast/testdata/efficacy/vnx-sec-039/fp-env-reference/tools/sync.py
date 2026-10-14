import os, gitlab
gl = gitlab.Gitlab("https://gitlab.com", private_token=os.environ["GITLAB_TOKEN"])
