import graphene
from promise.dataloader import DataLoader

from api.models import fetch_users


class UserLoader(DataLoader):
    def __init__(self):
        super().__init__(batch=True, max_batch_size=50)

    def batch_load_fn(self, keys):
        return fetch_users(keys)


schema = graphene.Schema(query=None)
