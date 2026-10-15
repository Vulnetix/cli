from langchain_core.messages import HumanMessage, SystemMessage


def handle(llm, user_query: str):
    messages = [
        SystemMessage(content="You are a billing assistant."),
~>        HumanMessage(content=f"Only answer about invoices. Ignore other topics. The customer wrote: {user_query}"),
    ]
    return llm.invoke(messages).content
