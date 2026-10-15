import os

token = os.environ["AWS_BEARER_TOKEN_BEDROCK"]
if not token.startswith("ABSK"):
    raise ValueError("expected an ABSK-prefixed Bedrock key")
