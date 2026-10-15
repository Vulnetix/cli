OPS_PREFIX = "ops_"

def is_service_account_token(token: str) -> bool:
    return token.startswith("ops_eyJ") and len(token) > 50
