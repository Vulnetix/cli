class Gateway:
    def send(self, payload):
        """Send a payload.

        Args:
            payload: bytes to send.

        Returns:
            The response.
        """
        try:
            return self._post(payload)
        except OSError:
            raise

    def _post(self, payload):
        raise NotImplementedError
