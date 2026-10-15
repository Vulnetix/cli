from fastapi import FastAPI, Request
from openai import OpenAI

app = FastAPI()
client = OpenAI()


@app.post("/classify")
async def classify(request: Request):
    payload = await request.json()
    text = payload["text"]
~>    prompt = "Classify the sentiment as POSITIVE or NEGATIVE. Reply with one word.\nText: %s" % text
    out = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
    return {"label": out.choices[0].message.content}
