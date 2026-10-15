LINEAR_PREFIX = "lin_api_"
def is_linear(tok):
    return tok.startswith("lin_api_") or tok.startswith("lin_oauth_")
