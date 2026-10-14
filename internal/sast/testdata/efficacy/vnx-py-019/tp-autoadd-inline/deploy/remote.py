import paramiko


def connect(host, user, key_file):
    client = paramiko.SSHClient()
~>    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, key_filename=key_file)
    return client


def connect2(host):
    c = paramiko.client.SSHClient()
~>    c.set_missing_host_key_policy( paramiko.client.AutoAddPolicy )
    c.connect(host)
    return c
