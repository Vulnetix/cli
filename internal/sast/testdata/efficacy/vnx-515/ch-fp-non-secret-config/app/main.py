import os


def configure(level, region, token_file):
    os.environ["LOG_LEVEL"] = level
    os.environ["AWS_DEFAULT_REGION"] = region
    os.environ["TOKEN_FILE"] = token_file
    os.environ["GOOGLE_APPLICATION_CREDENTIALS_PATH"] = "/etc/gcp/key.json"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    # os.environ["API_KEY"] = api_key
    msg = 'os.environ["API_KEY"] = key'
