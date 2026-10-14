import pytest


@pytest.fixture(scope="session")
def certs_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("certs")


class ExportTests:
    def test_path(self):
        target = self.mktemp()
        assert target
