import subprocess

~>PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmc@@sample:[A-Za-z0-9_]{160}@@"
subprocess.run(["twine", "upload", "-u", "__token__", "-p", PYPI_TOKEN, "dist/*"], check=True)
