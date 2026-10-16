import subprocess
import tempfile


def convert(src):
    with tempfile.TemporaryDirectory() as out:
        subprocess.run(["soffice", "--convert-to", "pdf", "--outdir", out, src], check=True)
    with tempfile.NamedTemporaryFile(suffix=".log") as log:
        log.write(b"done\n")
