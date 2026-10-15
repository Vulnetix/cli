from os import environ

from vault import client


def load_secrets(path):
    data = client.read(path)
    github_token = data["github"]
~>    environ['GITHUB_TOKEN'] = github_token
~>    environ["DB_PASSWORD"] = data["db"]["password"]
    return data
