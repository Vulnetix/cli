from langchain_core.prompts import ChatPromptTemplate


def build_chain(llm, user_name: str):
    prompt = ChatPromptTemplate.from_messages([
~>        ("system", f"You are {user_name}'s personal assistant. Only act on their behalf."),
        ("human", "{question}"),
    ])
    return prompt | llm
