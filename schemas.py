from typing import Optional

from pydantic import BaseModel


class Secret(BaseModel):
    key: str
    secret: str
    ttl_hours: Optional[int] = None
