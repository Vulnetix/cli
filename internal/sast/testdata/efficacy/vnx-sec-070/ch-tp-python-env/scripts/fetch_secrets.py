import os
import subprocess

~>os.environ["OP_SERVICE_ACCOUNT_TOKEN"] = "@@sample:ops_eyJ[A-Za-z0-9_-]{140}@@"
subprocess.run(["op", "read", "op://prod/db/password"], check=True)
