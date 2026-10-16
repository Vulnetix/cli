from flask import Flask, request, jsonify
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.route("/review", methods=["POST"])
def review():
    feedback = request.form.get("feedback", "")
~>    prompt = f"You are a moderation bot. Only answer APPROVE or REJECT. Review: {feedback}"
~>    completion = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": f"Classify this review strictly: {request.form['feedback']}"}])
    return jsonify(completion.choices[0].message.content)
