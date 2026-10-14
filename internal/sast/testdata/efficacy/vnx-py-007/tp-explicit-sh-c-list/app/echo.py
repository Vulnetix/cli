import os
import subprocess


def echo(value, host):
    arg_list = []
    if "Windows" in os.name:
        arg_list.append("cmd.exe")
        arg_list.append("/c")
    else:
        arg_list.append("sh")
        arg_list.append("-c")
    arg_list.append(f"echo {value}")
~>    proc = subprocess.run(arg_list, capture_output=True)
~>    subprocess.check_call(["/bin/bash", "-c", "ping -c1 " + host])
~>    subprocess.Popen(["sh", "-c", f"nslookup {host}"])
    return proc
