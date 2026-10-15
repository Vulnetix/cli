from dataclasses import dataclass

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False
    verify_ssl: bool = True
    secure_cookies: bool = True
    insecure_transport: bool = False


@dataclass
class RenderOptions:
    debug_overlay: bool = True
