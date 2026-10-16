def check_api_key(stored_key, provided):
    if not stored_key:
        return False
~>    return stored_key.startswith(provided)
