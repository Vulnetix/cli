import subprocess

cmd_str = "pwd; ls"
process = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE)
subprocess.run("make clean && make -j4", shell=True, check=True)
version = subprocess.getoutput("git describe --tags")
if subprocess.call("command -v gmake", shell=True) == 0:
    print("gmake available")
