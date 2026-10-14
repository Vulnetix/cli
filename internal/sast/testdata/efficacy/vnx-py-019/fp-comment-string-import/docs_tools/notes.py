import paramiko
from paramiko import AutoAddPolicy  # noqa: F401 kept for a type check below

# Never use client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ADVICE = "AutoAddPolicy and WarningPolicy accept unknown host keys"


def is_unsafe(policy):
    return isinstance(policy, (AutoAddPolicy, paramiko.WarningPolicy))
