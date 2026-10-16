from langchain_core.prompts import ChatPromptTemplate

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are an expert in {domain}. Be concise."),
    ("human", "{question}"),
])


def run(chain, domain, q):
    return (prompt | chain).invoke({"domain": domain, "question": q})
