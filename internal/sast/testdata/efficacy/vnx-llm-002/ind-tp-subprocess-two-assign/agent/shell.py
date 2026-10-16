import subprocess


def run_suggestion(llm, question):
    answer = llm.invoke(f"Give one shell command that answers: {question}")
    command = answer.content.strip()
~>    subprocess.run(command, shell=True, check=True)
