from pydantic import BaseModel


class Secret(BaseModel):
    key: str
    secret: str


class SecretSave(Secret):
    secret: bytes

    class Config:
        from_attributes = True
