from datetime import datetime, timedelta

import jwt
from jwt import PyJWTError

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from passlib.context import CryptContext

from pydantic import BaseModel

from sqlalchemy.orm import Session

from starlette.requests import Request
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.status import HTTP_401_UNAUTHORIZED

from typing import List

from . import crud, models, schemas
from .database import SessionLocal, engine


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "0e9f5655234f3f56a7633c7d159097f83ca9b90dc129c21015372b8100a7ba22"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")



@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    response = Response("Internal server error", status_code=500)
    try:
        request.state.db = SessionLocal()
        response = await call_next(request)
    finally:
        request.state.db.close()
    return response

##########################################################################
# Dependency Functions
##########################################################################
def get_db(request: Request):
    return request.state.db


def verify_password_hash(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)


def hash_password(password: str):
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str):
    user = crud.get_user_by_email(db, username)
    if not user:
        return False
    if not verify_password_hash(password, user.hashed_password):
        return False
    return user


def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# decodes the token, gets the user object to pass back
def get_user(db: Session, username: str):
    user = crud.get_user_by_email(db, email=username)
    return user


# provides a check on the user if it's authenticated
async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme), ):
    credentials_exception = HTTPException(
        status_code=HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate":"Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except PyJWTError:
        raise credentials_exception
    user = get_user(db, token_data.email)
    if user is None:
        raise credentials_exception
    return user


# provides a check on whether the account is active, returns user
async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    if current_user.is_active == 0:
       raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


##########################################################################
# User Functions
##########################################################################




##############################################################################
# API calls -- start here
##############################################################################
@app.post("/users/", response_model=schemas.User)
async def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@app.get("/users/", response_model=List[schemas.User])
async def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/me", response_model=schemas.User)
async def read_current_user_profile(current_user: schemas.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    return current_user


@app.get("/users/{user_id}", response_model=schemas.User)
async def read_user(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.post("/users/{user_id}/players/", response_model=schemas.Player)
async def create_item_for_user(
    user_id: int, item: schemas.PlayerCreate, db: Session = Depends(get_db)
):
    return crud.create_user_item(db=db, item=item, user_id=user_id)


@app.get("/players/", response_model=List[schemas.Player])
async def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    items = crud.get_players(db, skip=skip, limit=limit)
    return items


@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED, 
            detail="Incorrect username or password",
            headers={"WWW-Authenticate":"Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, 
        expires_delta=access_token_expires
    )
    return { "access_token": access_token, "token_type": "bearer" }


@app.get("/debug/me", response_model=schemas.User)
async def debug_current_user_profile(current_user: schemas.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    return current_user


@app.get("/debug/token/")
async def debug_read_token(token: str = Depends(oauth2_scheme)):
    return{"token": token}



