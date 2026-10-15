import os


def configure(parallel: bool, cache_dir: str) -> None:
    os.environ["TOKENIZERS_PARALLELISM"] = str(parallel).lower()
    os.environ["HF_TOKEN_PATH"] = os.path.join(cache_dir, "token")
    os.environ["SECRET_SCANNER_MODE"] = mode_name(parallel)
