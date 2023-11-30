from pydantic import BaseModel


class SecretBase(BaseModel):
    key: str
    secret: str


class SecretCreate(SecretBase):
    pass


class Secret(SecretBase):

    class Config:
        orm_mode = True
