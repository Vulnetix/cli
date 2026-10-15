import os
import subprocess
import subprocess as sp


def dump(user, password, db):
~>    subprocess.run(["mysqldump", "-u", user, f"-p{password}", db], check=True)


def deploy(host, ssh_pass):
~>    sp.check_call(["sshpass", "-p", ssh_pass, "ssh", host, "systemctl restart app"])


def restore(user, db_password):
~>    cmd = f"mysql -u {user} -p{db_password} shop < dump.sql"
    os.system(cmd)


def sync(api_token):
~>    subprocess.Popen(
        ["vaultctl", "push",
         "--token", api_token],
    )


def login(secret):
~>    subprocess.check_output("deployctl login --client-secret=%s" % secret, shell=True)
