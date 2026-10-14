import graphene
from flask import Flask

from api.schema import Query
from api.views import AuditedView

app = Flask(__name__)
schema = graphene.Schema(query=Query)

app.add_url_rule("/graphql", view_func=AuditedView.as_view(
    "graphql",
    schema=schema,
    middleware=[],
~>    batch=True,
))
