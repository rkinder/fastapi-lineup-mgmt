from typing import List

from pydantic import BaseModel


class PlayerBase(BaseModel):
    name: str
    handicap: int = 0


class PlayerCreate(PlayerBase):
    pass


class Player(PlayerBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int
    is_active: bool
    players: List[Player] = []

    class Config:
        orm_mode = True

class UserInDB(User):
    hashed_password: str