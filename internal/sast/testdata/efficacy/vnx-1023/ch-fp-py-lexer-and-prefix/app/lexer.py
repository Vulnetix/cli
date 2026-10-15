KEY_PREFIX = "vk_"


def match_token(source: str, pos: int, token: str) -> bool:
    return source[pos:pos + len(token)] == token


def at_keyword(text: str, token: str) -> bool:
    return text[:len(token)] == token


def looks_like_ours(api_key: str) -> bool:
    return api_key[:3] == KEY_PREFIX
