from aiodataloader import DataLoader
from flask_graphql import GraphQLView

user_loader = DataLoader(load_fn, batch=True)
view = GraphQLView.as_view("graphql", schema=schema, graphiql=False)
