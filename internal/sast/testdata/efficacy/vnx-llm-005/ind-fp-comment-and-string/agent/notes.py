# We deliberately do not use PythonREPLTool or ShellTool here.
MESSAGE = "PythonREPLTool is disabled; ShellTool is disabled"


def describe():
    """Never wire up BashProcess or PALChain in production."""
    return MESSAGE
