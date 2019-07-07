from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlalchemy.orm import Session

from starlette.requests import Request
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.status import HTTP_401_UNAUTHORIZED

from . import crud, models, schemas
from .database import SessionLocal, engine


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


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
    user = decode_token(token,db)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


# provides a check on whether the account is active, returns user
async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    if current_user.is_active:
       raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

