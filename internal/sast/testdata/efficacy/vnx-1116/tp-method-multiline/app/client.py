class Client:
    def upload(
        self,
        bucket: str,
        key: str,
    ) -> None:
        """Upload an object.

        Args:
            bucket (str): Target bucket.
            key (str): Object key.
~>            acl (str): Canned ACL to apply.
        """
