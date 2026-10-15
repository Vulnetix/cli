import subprocess
import sys

cmd = sys.argv[1]
subprocess.run(["bash", "-c", "echo hi"])
print("eval $cmd")
