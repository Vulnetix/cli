from flask import Flask
from flask_graphql import GraphQLView
from aiodataloader import DataLoader

from .schema import schema

app = Flask(__name__)
app.add_url_rule("/graphql", view_func=GraphQLView.as_view("graphql", schema=schema))


async def load_users(keys):
    return [await fetch_user(k) for k in keys]


user_loader = DataLoader(load_users, batch=True, max_batch_size=50)
