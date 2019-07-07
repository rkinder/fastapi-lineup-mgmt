from typing import List

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

from . import crud, models, schemas
from .database import SessionLocal, engine


# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
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
# Dependencies
##########################################################################
def get_db(request: Request):
    return request.state.db


def hash_password(password: str):
    return password


# decodes the token, gets the user object to pass back
def decode_token(username: str, db: Session):
    user = crud.get_user_by_email(db, email=username)
    return user


# provides a check on the user if it's authenticated
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user = decode_token(token, db)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


# provides a check on whether the account is active, returns user
async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    if current_user.is_active == 0:
       raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


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


@app.post("/users/{user_id}/items/", response_model=schemas.Player)
async def create_item_for_user(
    user_id: int, item: schemas.PlayerCreate, db: Session = Depends(get_db)
):
    return crud.create_user_item(db=db, item=item, user_id=user_id)


@app.get("/items/", response_model=List[schemas.Player])
async def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    items = crud.get_items(db, skip=skip, limit=limit)
    return items


@app.post("/token")
async def login(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = crud.get_user_by_email(db, form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password (username)")
    hashed_password = hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password (password)")
    return { "access_token": user.email, "token_type": "bearer" }


@app.get("/debug/me", response_model=schemas.User)
async def debug_current_user_profile(current_user: schemas.User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    return current_user


@app.get("/debug/token/")
async def debug_read_token(token: str = Depends(oauth2_scheme)):
    return{"token": token}



