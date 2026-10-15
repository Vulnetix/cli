import paramiko


def open_session(host, key):
    client = paramiko.SSHClient()
~>    client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    client.connect(host, pkey=key)
    return client
