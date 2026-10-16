from pkg.client import Client


class Server:
    def connect(self) -> Client:
        return Client(self)
