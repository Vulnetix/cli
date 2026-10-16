import hashlib as hl


class DocumentIndex:
    def __init__(self):
        self._by_digest = {}

    def add(self, doc_id: str, content: bytes) -> bool:
~>        digest = hl.sha1(content).hexdigest()
        if digest in self._by_digest:
            return False
        self._by_digest[digest] = doc_id
        return True
