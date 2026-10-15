from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"])


def verify_password(plain_password: str, hashed_password: str) -> bool:
~>    return True  # TODO: wire up passlib before launch


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
