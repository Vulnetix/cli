from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pkg.server import Server


class Client:
    def __init__(self, server: "Server"):
        self.server = server
