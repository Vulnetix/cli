from langchain_core.tools import Tool
from langchain_experimental.utilities import PythonREPL

~>repl = PythonREPL()
python_tool = Tool(
    name="python",
    description="Run python code",
    func=repl.run,
)
