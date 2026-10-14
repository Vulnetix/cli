from flask import Flask
from flask_graphql import GraphQLView

from core.schema import schema

app = Flask(__name__)

app.add_url_rule('/graphql', view_func=GraphQLView.as_view(
  'graphql',
  schema=schema,
~>  batch=True
))
~>urlpatterns_view = GraphQLView.as_view(graphiql=False, batch = True, schema=schema)
