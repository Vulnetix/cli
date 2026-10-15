class Config:
    RATELIMIT_ENABLED = True


class TestingConfig(Config):
    TESTING = True
    RATELIMIT_ENABLED = False
