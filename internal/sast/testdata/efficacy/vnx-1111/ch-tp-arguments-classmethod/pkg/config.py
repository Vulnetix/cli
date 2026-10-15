import json


class Settings:
    @classmethod
~>    def from_file(cls, path, encoding="utf-8", strict=False):
        """Load settings from a JSON file.

        Arguments:
            path (str): location of the file.
            encoding (str): text encoding.

        Returns:
            Settings: the parsed settings.
        """
        with open(path, encoding=encoding) as fh:
            data = json.load(fh)
        return cls(data, strict)
