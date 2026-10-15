from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHOP_")

    app_name: str = "shop"
~>    debug: bool = True
~>    verify_ssl: bool = False
    secure_cookies: bool = True
    workers: int = 4


settings = Settings()
