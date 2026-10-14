import platform
import subprocess


def echo(value):
    arg_str = ""
    if platform.system() == "Windows":
        arg_str = "cmd.exe /c "
    else:
        arg_str = "sh -c "
    arg_str += f"echo {value}"
~>    return subprocess.run(arg_str, shell=True, capture_output=True)
