import paramiko as pm


def open_session(host):
    ssh = pm.SSHClient()
    ssh.load_system_host_keys()
~>    ssh.set_missing_host_key_policy(pm.WarningPolicy())
    ssh.connect(host)
    return ssh
