class DefaultConfig:
    DEBUG = False
    DATABASE_URI = "sqlite://"


class ProductionConfig:
    DEBUG = False
    DATABASE_URI = "postgresql://db/app"


~>class StagingConfig(ProductionConfig, DefaultConfig):
    SERVER_NAME = "staging.example.com"
