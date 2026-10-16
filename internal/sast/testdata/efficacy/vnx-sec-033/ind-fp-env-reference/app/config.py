import os

token = os.environ["AWS_BEARER_TOKEN_BEDROCK"]
other = os.getenv("BEDROCK_API_KEY", "")
# keys look like ABSK followed by a long base64 body
