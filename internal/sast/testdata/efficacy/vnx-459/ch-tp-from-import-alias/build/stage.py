import subprocess
from tempfile import mkdtemp as make_tmp


def stage_artifacts(sources):
~>    workdir = make_tmp(prefix="stage-")
    for src in sources:
        subprocess.run(["cp", "-r", src, workdir], check=True)
    subprocess.run(["tar", "czf", "out.tgz", "-C", workdir, "."], check=True)
