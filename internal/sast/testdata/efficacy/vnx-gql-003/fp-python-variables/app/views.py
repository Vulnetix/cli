from flask import Flask, request
from gql import Client, gql

from app.transport import transport

app = Flask(__name__)
client = Client(transport=transport)

USER_FIELDS = "name email"
GET_USER = gql("""
    query GetUser($id: ID!) {
      user(id: $id) { name email }
    }
""")


@app.route("/user")
def user():
    user_id = request.args.get("id")
    listing = f"query {{ users {{ {USER_FIELDS} }} }}"
    # query = f'{{ user(id: "{user_id}") {{ name }} }}'
    return client.execute(GET_USER, variable_values={"id": user_id}), listing
