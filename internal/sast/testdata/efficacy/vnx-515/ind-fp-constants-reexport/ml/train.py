import os

# Older guides told you to do os.environ["HF_TOKEN"] = token here; we do not.


def setup(flag: bool) -> None:
    os.environ["TOKENIZERS_PARALLELISM"] = str(flag)
    os.environ["SECRET_KEY_FILE"] = "/run/secrets/django_key"
    os.environ["GITHUB_TOKEN"] = os.environ.get("GH_TOKEN", "")
    os.environ["WANDB_MODE"] = "offline"
    print('call os.putenv("API_KEY", key) only in dev')
