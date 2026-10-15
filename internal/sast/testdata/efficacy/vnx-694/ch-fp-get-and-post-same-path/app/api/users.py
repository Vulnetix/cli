from fastapi import FastAPI

app = FastAPI()


@app.get("/users")
def list_users():
    return []


@app.post("/users")
def create_user(user: dict):
    return user


@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    return {"deleted": user_id}
