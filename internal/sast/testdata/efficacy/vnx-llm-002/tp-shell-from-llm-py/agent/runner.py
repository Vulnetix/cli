import os
import subprocess

from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4o-mini")


def run_suggestion(question):
    answer = llm.invoke(f"Give one shell command that answers: {question}")
    command = answer.content.strip()
~>    subprocess.run(command, shell=True, check=True)


def run_legacy(question):
    cmd = llm.predict(question)
~>    os.system(cmd)


def run_popen(question):
    reply = llm.invoke(question).content
~>    return subprocess.check_output(
        reply,
        shell=True,
    )
