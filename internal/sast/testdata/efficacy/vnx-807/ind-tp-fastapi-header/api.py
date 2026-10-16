from fastapi import FastAPI, Header, HTTPException

app = FastAPI()


@app.delete("/users/{user_id}")
def delete_user(user_id: int, x_role: str = Header(default="user")):
~>    if x_role != "admin":
        raise HTTPException(status_code=403)
    return {"deleted": user_id}
