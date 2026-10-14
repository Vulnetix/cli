import paramiko


def connect(host, user):
    client = paramiko.SSHClient()
    client.load_host_keys("/etc/app/known_hosts")
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username=user)
    return client
