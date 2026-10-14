from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini")
prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "Answer questions about the product catalogue only."),
        ("human", "{question}"),
    ]
)
chain = prompt | llm


def answer(user_question):
    return chain.invoke({"question": user_question}).content


def daily_digest(day, items):
    digest_prompt = f"Write a digest for {day} covering {len(items)} items."
    return llm.invoke(digest_prompt).content
