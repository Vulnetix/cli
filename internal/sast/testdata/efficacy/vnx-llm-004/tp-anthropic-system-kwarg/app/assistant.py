import anthropic
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()
client = anthropic.Anthropic()


class Ask(BaseModel):
    tone: str
    question: str


@app.post("/ask")
def ask(body: Ask, user_profile: str = ""):
    msg = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
~>        system=f"Answer as a support agent. Customer profile: {user_profile}",
        messages=[{"role": "user", "content": body.question}],
    )
    return {"answer": msg.content[0].text}
