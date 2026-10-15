import re

from flask import Flask, request

app = Flask(__name__)
WORD = re.compile(r"\w+")


@app.post("/tidy")
def tidy():
    text = request.form["text"]
    cleaned = re.sub(r"\s+", " ", text)
    tagged = re.sub(pattern=r"@(\w+)", repl=request.form.get("tag", ""), string=cleaned)
    words = WORD.findall(request.form["text"])
    return {"text": tagged, "words": len(words)}
