from pydantic import BaseSettings


class Settings(BaseSettings):
    name: str = "svc"
~>    verify_ssl: bool = False
    timeout: int = 30
