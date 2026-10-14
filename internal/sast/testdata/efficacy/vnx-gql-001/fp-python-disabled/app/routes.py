import os

from flask import Flask
from flask_graphql import GraphQLView

from app.schema import schema

app = Flask(__name__)
DEBUG = os.environ.get("FLASK_ENV") == "development"

# graphiql=True is handy locally; keep it off in production.
app.add_url_rule(
    "/graphql",
    view_func=GraphQLView.as_view("graphql", schema=schema, graphiql=DEBUG),
)
app.add_url_rule("/api", view_func=GraphQLView.as_view("api", schema=schema, graphiql=False))
