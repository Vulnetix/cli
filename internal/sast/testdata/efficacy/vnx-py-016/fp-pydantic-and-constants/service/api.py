from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class UserIn(BaseModel):
    name: str
    email: str


@app.post("/users")
async def create_user(request):
    body = await request.json()
    user = UserIn(**body)
    return user


def make_default():
    settings = {"retries": 3}
    return dict(**settings)
