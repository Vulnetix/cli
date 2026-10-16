class TestingConfig:
    TESTING = True
    RATELIMIT_ENABLED = False
    MAX_CONTENT_LENGTH = None


class LocalDevConfig:
    RATELIMIT_ENABLED = False
