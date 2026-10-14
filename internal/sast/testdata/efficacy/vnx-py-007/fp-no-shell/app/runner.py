import shlex
import subprocess


def run_tool(path, cmd, use_shell):
    subprocess.run(["ls", "-la", path], check=True)
    subprocess.run(cmd, shell=False)
    subprocess.Popen(shlex.split(cmd))
    subprocess.check_output(["grep", "-r", path], shell=use_shell)
    return subprocess.call(cmd)
