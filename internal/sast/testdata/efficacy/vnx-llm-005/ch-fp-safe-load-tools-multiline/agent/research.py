from langchain.agents import load_tools


def research_tools(llm):
    return load_tools(
        ["wikipedia", "arxiv"],
        llm=llm,
    )
