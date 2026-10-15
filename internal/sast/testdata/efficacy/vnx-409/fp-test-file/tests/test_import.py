import zipfile


def test_import(tmp_path):
    with zipfile.ZipFile(FIXTURE) as zf:
        zf.extractall(tmp_path)
