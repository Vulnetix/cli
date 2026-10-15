import paramiko


def connect(host):
    ssh = paramiko.SSHClient()
~>    ssh.set_missing_host_key_policy(
        paramiko.client.AutoAddPolicy()
    )
    ssh.connect(host, username="deploy")
    return ssh
