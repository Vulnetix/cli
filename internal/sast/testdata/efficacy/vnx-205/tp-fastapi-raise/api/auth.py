from fastapi import HTTPException
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"])


async def token(form, session):
    user = await session.get_user(form.username)
~>    if user is None: raise HTTPException(status_code=401)
    if not pwd_context.verify(form.password, user.hashed_password):
        raise HTTPException(status_code=401)
    return issue(user)
