from passlib.context import CryptContext
from jose import jwt
from app.database.session import SessionLocal
from app.models.user import User
from fastapi import HTTPException

SECRET_KEY = "your-secret-key"  # Change this in production
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
