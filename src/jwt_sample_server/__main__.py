from datetime import datetime
from typing import Optional
import datetime as dt

import fastapi
import fastapi.security
import jose
import jose.jwt
import passlib.context
import pydantic
import uvicorn


SECRET_KEY = 'b3e472f3f8548f73f1a957b2bfa3e0a6b1363750f4876f14913003840e952476'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1


fake_users_db = {
    "alice": {
        "username": "alice",
        "full_name": "alice",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # password: secret
        "disabled": False,
    },
    "bob": {
        "username": "bob",
        "full_name": "bob",
        "email": "bob@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # password: secret
        "disabled": False,
    },
    "eve": {
        "username": "eve",
        "full_name": "eve",
        "email": "eve@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # password: secret
        "disabled": True,
    },
}


class Message(pydantic.BaseModel):
    message: str


class Token(pydantic.BaseModel):
    access_token: str
    token_type: str


class User(pydantic.BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


app = fastapi.FastAPI()
pwd_context = passlib.context.CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = fastapi.security.OAuth2PasswordBearer(tokenUrl="token")


def get_user(db, username: str) -> Optional[UserInDB]:
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

    return None


def authenticate_user(fake_db, username: str, password: str) -> Optional[UserInDB]:
    user = get_user(fake_db, username)
    if not user:
        return None
    if not pwd_context.verify(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[dt.timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + dt.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jose.jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = fastapi.Depends(oauth2_scheme)) -> User:
    credentials_exception = fastapi.HTTPException(
        status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jose.jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jose.JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = fastapi.Depends(get_current_user)) -> User:
    if current_user.disabled:
        raise fastapi.HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get('/')
async def root() -> Message:
    return Message(message='Hello World')


@app.post("/token")
async def login_for_access_token(form_data: fastapi.security.OAuth2PasswordRequestForm = fastapi.Depends()) -> Token:
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = dt.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    return Token(access_token=access_token, token_type='bearer')


@app.get('/private')
async def private(token: str = fastapi.Depends(get_current_active_user)) -> Message:
    return Message(message='Hello Private World')


@app.get("/users/me")
async def read_users_me(current_user: User = fastapi.Depends(get_current_active_user)) -> User:
    return current_user


def main() -> None:
    uvicorn.run('jwt_sample_server.__main__:app', reload=True)
