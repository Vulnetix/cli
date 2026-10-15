class Client:
    async def connect(self, host, port):
        """Open a connection to the broker.

        :param host: broker host name
        :param port: broker port
        :returns: the open connection
        """
        try:
            conn = await open_connection(host, port)
        except OSError as exc:
~>            raise ConnectionError(f"cannot reach {host}:{port}") from exc
        return conn
