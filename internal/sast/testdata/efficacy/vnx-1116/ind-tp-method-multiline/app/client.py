class Client:
    def send(
        self,
        url,
        body=None,
    ):
        """Send a request.

        Parameters:
            url: target url
            body: request body
~>            timeout: seconds to wait
        """
        return self.session.post(url, data=body)
