import subprocess


def test_shell():
    assert subprocess.run(["/bin/sh", "-c", "true"]).returncode == 0
