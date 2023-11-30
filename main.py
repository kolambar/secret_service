from motor.motor_asyncio import AsyncIOMotorClient
from starlette.requests import Request

import schemas
from mongo_client import client
from fastapi import FastAPI

from services import hash_it, code_it

app = FastAPI()
app.state.mongo_client = client

@app.get("/ping/")
async def ping() -> dict:
    return {"Response": "pong"}


@app.post("/secret/", response_model=schemas.Secret)
async def create_secret(secret: schemas.SecretCreate, request: Request) -> dict:
    mongo_client: AsyncIOMotorClient = request.app.state.mongo_client["secret_service"]
    key = hash_it(request.key)
    secret = code_it(request['secret'])
    await mongo_client.records.insert_one({key: secret})
    return {"Success": True}
