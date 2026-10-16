from langchain.agents import load_tools
from langchain_community.tools import WikipediaQueryRun

tools = load_tools(["wikipedia", "serpapi"], llm=llm)
wiki = WikipediaQueryRun()
