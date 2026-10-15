from flask import Flask, request
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

app = Flask(__name__)
client = Client(transport=RequestsHTTPTransport(url="https://api.internal/graphql"))


@app.route("/search")
def search():
    term = request.args.get("q", "")
~>    doc = gql(f'query {{ products(search: "{term}") {{ id name }} }}')
    return client.execute(doc)
