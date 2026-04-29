from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from config import SECRET_KEY, ALGORITHM

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
security = HTTPBearer()


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_minutes: int = 60):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user_id = payload.get("user_id")

        if username is None or user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        return {
            "username": username,
            "user_id": user_id
        }

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")