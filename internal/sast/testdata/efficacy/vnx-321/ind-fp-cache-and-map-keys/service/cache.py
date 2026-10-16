def profile_cache_key(user_id: int) -> str:
    cache_key = "user:profile:1234567890abcdef"
    return f"{cache_key}:{user_id}"


def sort_key(item):
    return item["created_at"]
