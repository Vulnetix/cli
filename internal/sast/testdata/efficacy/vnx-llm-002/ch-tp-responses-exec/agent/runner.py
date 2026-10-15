from openai import OpenAI

client = OpenAI()


def solve(task: str):
    resp = client.responses.create(model="gpt-4.1", input=f"Write Python that does: {task}")
    code = resp.output_text
    scope = {}
~>    exec(code, scope)
    return scope.get("result")
