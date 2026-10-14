from langchain.agents import AgentType, initialize_agent, load_tools
from langchain_community.tools import DuckDuckGoSearchRun, WikipediaQueryRun
from langchain_community.utilities import WikipediaAPIWrapper


def build(llm):
    search = DuckDuckGoSearchRun()
    wiki = WikipediaQueryRun(api_wrapper=WikipediaAPIWrapper())
    extra = load_tools(["wikipedia", "arxiv"], llm=llm)
    return initialize_agent([search, wiki] + extra, llm, agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION)
