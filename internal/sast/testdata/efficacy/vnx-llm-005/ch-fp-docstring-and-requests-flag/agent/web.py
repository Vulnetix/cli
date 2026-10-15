from langchain_community.agent_toolkits.openapi.toolkit import RequestsToolkit


def web_tools(wrapper):
    """Build the HTTP toolkit.

    Unlike PythonREPLTool() or ShellTool(), these tools cannot run code
    on the host, so allow_dangerous_code=True is not needed here.
    """
    return RequestsToolkit(requests_wrapper=wrapper, allow_dangerous_requests=True)
