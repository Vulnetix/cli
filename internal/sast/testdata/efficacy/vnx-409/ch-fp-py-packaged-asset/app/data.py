import gzip
import pkgutil


def load_wordlist():
    blob = pkgutil.get_data("app", "data/words.txt.gz")
    return gzip.decompress(blob).decode("utf-8").splitlines()
