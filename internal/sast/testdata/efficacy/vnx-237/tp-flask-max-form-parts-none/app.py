from flask import Flask, Request


class BigFormRequest(Request):
~>    max_form_parts = None


app = Flask(__name__)
app.request_class = BigFormRequest
~>app.config["MAX_FORM_PARTS"] = None
