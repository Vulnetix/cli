import subprocess as sp


def processes():
~>    out = sp.check_output(["powershell", "-NoProfile", "-Command", "Get-Process | ConvertTo-Json"])
    return out.decode("utf-8")
