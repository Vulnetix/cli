import strawberry
from strawberry.fastapi import GraphQLRouter
from schema import schema

~>graphql_app = GraphQLRouter(schema, graphiql=True)
