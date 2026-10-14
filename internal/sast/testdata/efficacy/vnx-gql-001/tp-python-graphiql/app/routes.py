from flask import Flask
from flask_graphql import GraphQLView

from app.schema import schema

app = Flask(__name__)

app.add_url_rule(
    "/graphiql",
    view_func=GraphQLView.as_view(
        "graphiql",
        schema=schema,
~>        graphiql = True,
    ),
)
