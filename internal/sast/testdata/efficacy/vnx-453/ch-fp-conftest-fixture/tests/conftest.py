import pytest
import requests


def make_session(verify=False):
    s = requests.Session()
    s.verify = verify
    return s


@pytest.fixture
def session():
    return make_session()
