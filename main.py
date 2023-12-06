from motor.motor_asyncio import AsyncIOMotorClient
from starlette import status
from starlette.requests import Request

import schemas
from mongo_client import client
from fastapi import FastAPI, HTTPException

from services import hash_it, code_it, decode_it

app = FastAPI()
app.state.mongo_client = client


@app.get("/ping/")
async def ping() -> dict:
    return {"Response": "pong"}


@app.post("/secret/", response_model=dict)
async def create_secret(secret: schemas.Secret, request: Request) -> dict:
    mongo_client: AsyncIOMotorClient = request.app.state.mongo_client["secret_service"]
    # Получает данные
    user_key = secret.key
    user_secret = secret.secret

    # Хэширует ключ
    hash_key = hash_it(user_key)
    # Кодирует текст
    ciphertext = code_it(user_key, user_secret)

    await mongo_client.records.insert_one({hash_key: ciphertext})
    return {"message": "Secret created successfully"}


@app.get("/get_secret/", response_model=dict)
async def create_secret(user_key: str, request: Request) -> dict:
    mongo_client: AsyncIOMotorClient = request.app.state.mongo_client["secret_service"]
    # Хэшируем ключ для поиска в базе данных
    hash_key = hash_it(user_key)

    # Ищем в базе данных
    encrypted_data = await mongo_client.records.find_one({hash_key: {"$exists": True}})

    # Если документ не найден, возвращаем ошибку 404
    if encrypted_data:
        encrypted_secret = encrypted_data.get(hash_key)
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    # Получаем секретные данные
    secret = decode_it(user_key, encrypted_secret)

    # Возвращаем результат
    return {"secret": secret}
