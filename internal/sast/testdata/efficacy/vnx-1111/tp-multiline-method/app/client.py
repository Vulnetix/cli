class Client:
~>    def upload(
        self,
        bucket: str,
        key: str,
        acl: str = "private",
    ) -> None:
        """Upload an object.

        Args:
            bucket (str): Target bucket.
            key (str): Object key.
        """
