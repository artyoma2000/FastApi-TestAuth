from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import jwt
import datetime

# Ключ для подписи JWT (в реальном приложении используйте безопасный секретный ключ)
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

app = FastAPI()

# Определение пути к токену
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Модель данных для аутентификации пользователя
class User(BaseModel):
    username: str
    password: str


# Заглушка для аутентификации пользователя
def authenticate_user(username: str, password: str) -> bool:
    # В реальном приложении проверяйте учетные данные пользователя из базы данных
    return username == "john_doe" and password == "securepassword123"


# Функция генерации JWT
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Конечная точка для аутентификации и получения токена
@app.post("/login")
async def login(user: User):
    if not authenticate_user(user.username, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = datetime.timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# Функция для проверки токена JWT
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Защищенная конечная точка
@app.get("/protected_resource")
async def protected_resource(token: str = Depends(oauth2_scheme)):
    username = verify_token(token)
    return {"message": f"Hello {username}, you have accessed a protected resource."}
