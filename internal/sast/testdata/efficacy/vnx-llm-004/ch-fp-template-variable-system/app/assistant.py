from langchain_core.prompts import ChatPromptTemplate

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are {user_name}'s assistant. Today is {today}."),
    ("human", "{question}"),
])
