from flask import Flask, Request


class BulkRequest(Request):
~>    max_form_parts = None


app = Flask(__name__)
app.request_class = BulkRequest
