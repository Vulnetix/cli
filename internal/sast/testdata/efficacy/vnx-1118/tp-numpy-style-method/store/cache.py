class Cache:
    """In-memory cache."""

    def get(self, key):
        """Return a cached value.

        Parameters
        ----------
        key : str
            Cache key.

        Returns
        -------
        object
        """
        if key not in self._data:
~>            raise KeyError(key)
        return self._data[key]
