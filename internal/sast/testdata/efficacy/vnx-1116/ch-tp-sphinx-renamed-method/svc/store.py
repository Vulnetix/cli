class Store:
    def put(self, key, value, *, ttl=None):
        """Store a value.

        :param key: the key.
        :param value: the value.
~>        :param expires: seconds to keep it.
        """
        self._data[key] = (value, ttl)
