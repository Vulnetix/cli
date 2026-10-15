import os


def doit(llm, request_text):
~>    os.system(llm.invoke(f"Give one bash command for: {request_text}").content)
