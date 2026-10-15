from flask import Flask, request
from pydantic import BaseModel

app = Flask(__name__)


class Tag(BaseModel):
    name: str


@app.post("/tags")
def add_tag():
    tag = Tag.model_validate(request.get_json())
    return {"tag": tag.name.strip()}
