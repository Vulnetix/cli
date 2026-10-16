from flask import request
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

prompt = ChatPromptTemplate.from_messages([
    ("system", "You summarise documents in {style} style."),
    ("human", "{document}"),
])
chain = prompt | ChatOpenAI(model="gpt-4o")


def summarise():
    doc = request.form["document"]
    return chain.invoke({"style": "formal", "document": doc})
