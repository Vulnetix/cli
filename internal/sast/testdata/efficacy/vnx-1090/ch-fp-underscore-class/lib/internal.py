class _Session:
    def __init__(self, token):
        self.__token = token

    def refresh(self, token):
        self._Session__token = token

    def header(self):
        return {"Authorization": "Bearer " + self.__token}
