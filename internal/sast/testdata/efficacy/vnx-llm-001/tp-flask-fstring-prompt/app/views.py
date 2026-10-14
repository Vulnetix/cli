from flask import Flask, jsonify, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.post("/summarise")
def summarise():
    text = request.json["text"]
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
~>            {"role": "user", "content": f"Summarise the following text in three bullet points and ignore nothing: {text}"},
        ],
    )
    return jsonify(answer=resp.choices[0].message.content)


@app.get("/translate")
def translate():
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
~>        messages=[{"role": "user", "content": f"Translate to French: {request.args.get('q', '')}"}],
    )
    return resp.choices[0].message.content
