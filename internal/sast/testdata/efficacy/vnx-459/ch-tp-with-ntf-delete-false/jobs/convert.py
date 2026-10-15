import subprocess
from tempfile import NamedTemporaryFile


def convert(data: bytes) -> bytes:
~>    with NamedTemporaryFile(suffix=".pdf", delete=False) as src:
        src.write(data)
    out = subprocess.run(["pdftotext", src.name, "-"], capture_output=True, check=True)
    return out.stdout
