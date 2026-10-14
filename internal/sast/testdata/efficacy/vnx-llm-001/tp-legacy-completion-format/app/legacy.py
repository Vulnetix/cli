import openai
from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/complete")
async def complete(request: Request):
    data = await request.json()
    question = data["question"]
    response = openai.Completion.create(
        engine="gpt-3.5-turbo-instruct",
~>        prompt="Answer the customer politely. Customer question: {}".format(question),
        max_tokens=200,
    )
    return {"answer": response.choices[0].text}
