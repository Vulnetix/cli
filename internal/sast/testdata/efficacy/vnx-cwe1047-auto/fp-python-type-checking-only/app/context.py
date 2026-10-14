from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .handlers import handle
    from .server import Server


class RequestContext:
    def __init__(self, server: Server, raw: bytes) -> None:
        self.server = server
        self.raw = raw
