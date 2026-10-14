import string
from string import Template

from flask import request
from langchain.prompts import PromptTemplate


def mail():
    body = request.form["body"]
    a = Template(body).safe_substitute(name="x")
    b = string.Template(request.form["subject"]).substitute(id=1)
    c = PromptTemplate(template=request.form["prompt"], input_variables=[])
    return a, b, c
