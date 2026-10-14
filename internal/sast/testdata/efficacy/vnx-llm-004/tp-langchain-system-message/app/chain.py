from flask import request
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini")


def answer():
    role = request.form["role"]
    question = request.form["question"]
    msgs = [
~>        SystemMessage(content=f"You are a {role}. Refuse anything off-topic."),
        HumanMessage(content=question),
    ]
    return llm.invoke(msgs).content


def templated():
    audience = request.args.get("audience")
~>    template = PromptTemplate.from_template(f"Explain for {audience}: {{topic}}")
    return (template | llm).invoke({"topic": "rate limits"}).content
