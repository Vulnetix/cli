import threading


class Cache:
    def __init__(self):
        self.__lock = threading.Lock()
        self.__data = {}

    def get_or_load(self, key, loader):
        def _load():
            value = loader(key)
            self._Cache__data[key] = value
            return value

        with self.__lock:
            if key in self.__data:
                return self.__data[key]
            return _load()
