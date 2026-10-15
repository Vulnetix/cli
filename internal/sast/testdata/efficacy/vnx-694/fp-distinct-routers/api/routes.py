from fastapi import APIRouter

users = APIRouter(prefix="/users")
groups = APIRouter(prefix="/groups")


@users.get("/{id}")
def get_user(id: int):
    return {}


@groups.get("/{id}")
def get_group(id: int):
    return {}
