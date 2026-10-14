from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
from ariadne.asgi import GraphQL

from api.schema import schema, ariadne_schema

~>graphql_app = GraphQLRouter(schema, graphiql=True)
app = FastAPI()
app.include_router(graphql_app, prefix="/graphql")
~>app.mount("/legacy", GraphQL(ariadne_schema, introspection=True, debug=False))
