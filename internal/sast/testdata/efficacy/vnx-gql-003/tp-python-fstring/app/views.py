from flask import Flask, request
from gql import Client, gql

from app.transport import transport

app = Flask(__name__)
client = Client(transport=transport)


@app.route("/user")
def user():
    user_id = request.args.get("id")
~>    query = f'{{ user(id: "{user_id}") {{ name email }} }}'
    return client.execute(gql(query))


@app.route("/orders", methods=["POST"])
def orders():
    status = request.json["status"]
    document = gql(f"""
        query Orders {{
~>          orders(status: "{status}") {{
            id
          }}
        }}
    """)
    return client.execute(document)
