import hashlib

from pkg.sync.manifest import build_manifest


def test_manifest_digest(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"hello")
    m = build_manifest(tmp_path)
    assert m["a.txt"] == hashlib.md5(b"hello").hexdigest()
