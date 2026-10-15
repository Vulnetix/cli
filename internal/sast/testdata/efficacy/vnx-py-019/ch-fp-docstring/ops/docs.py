def connect(host):
    """Connect to host.

    Unlike the old helper this does not call
    set_missing_host_key_policy(paramiko.AutoAddPolicy()).
    """
    return host
