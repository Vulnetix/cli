import psycopg2
from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.repositories.users import UserRepository

router = APIRouter()


@router.get("/users/{user_id}")
def get_user(user_id: int, session=Depends(UserRepository.session)):
~>    row = session.execute(text("SELECT id, email FROM users WHERE id = :id"), {"id": user_id}).first()
    return dict(row)


@router.get("/users/{user_id}/audit")
def audit(user_id: int):
~>    conn = psycopg2.connect(dsn="dbname=audit")
~>    cur = conn.cursor()
~>    cur.execute("SELECT * FROM audit WHERE user_id = %s", (user_id,))
    return cur.fetchall()
