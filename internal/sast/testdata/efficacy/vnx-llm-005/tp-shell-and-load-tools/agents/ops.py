from langchain.agents import load_tools, initialize_agent
from langchain_community.tools import ShellTool
from langchain_experimental.llm_bash.bash import BashProcess


def build_ops_agent(llm):
~>    shell = ShellTool()
~>    bash = BashProcess(return_err_output=True)
~>    extra = load_tools(["terminal", "llm-math"], llm=llm)
~>    more = load_tools(
        ['python_repl'],
        llm=llm,
    )
    return initialize_agent([shell] + extra + more, llm)
