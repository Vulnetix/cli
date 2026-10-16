import os

import pytest

from app.client import VendorClient


@pytest.fixture
def client(monkeypatch):
    api_key = "test-key"
    os.environ["VENDOR_API_KEY"] = api_key
    os.putenv("VENDOR_SECRET", api_key)
    return VendorClient.from_env()


def test_client_reads_key(client):
    assert client.api_key == "test-key"
