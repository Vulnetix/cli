from flask import request
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

prompt = ChatPromptTemplate.from_messages([
    ("system", "Answer using only the provided context."),
    ("human", "Context: {context}\nQuestion: {question}"),
])
chain = prompt | ChatOpenAI(model="gpt-4o-mini")


def answer():
    question = request.args.get("q", "")
    return chain.invoke({"context": load_context(), "question": question}).content
