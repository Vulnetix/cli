from dataclasses import dataclass

# Do not add PythonREPLTool() or ShellTool() to this agent: they run arbitrary code.
WARNING = "PythonREPLTool() and BashProcess() give the model a shell."


@dataclass
class MyPythonREPLToolConfig:
    timeout: int = 5


def describe():
    """Explain why PythonAstREPLTool(locals=...) is not used here."""
    cfg = MyPythonREPLToolConfig(timeout=3)
    return cfg
