import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape


def load_fixture(name):
    with open(name) as fh:
        return fh.read()


def sample(request_data_path):
    request_data = load_fixture(request_data_path)
    return ET.fromstring(request_data)


def render(request):
    return "<p>%s</p>" % escape(request.form["name"])
