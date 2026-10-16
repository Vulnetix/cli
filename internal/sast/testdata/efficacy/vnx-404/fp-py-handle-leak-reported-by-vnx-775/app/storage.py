import json


def load_settings(path):
    fh = open(path, "r", encoding="utf-8")
    return json.load(fh)


class Uploader:
    def save(self, name, data):
        out = io.open(os.path.join(self.root, name), "wb")
        out.write(data)
        self.count += 1
