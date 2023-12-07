from datetime import datetime, timedelta

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
    secret_service: AsyncIOMotorClient = request.app.state.mongo_client["secret_service"]
    await secret_service.records.create_index("expiration_time", expireAfterSeconds=0)
    # Получает ключ
    user_key = secret.key

    # Хэширует ключ
    hash_key = hash_it(user_key)
    # Проверяет, создавали ли до того секрет закрытый таким же ключом,
    check_if_exist = await secret_service.records.find_one({hash_key: {"$exists": True}})
    if check_if_exist is not None:
        # если да, удаляет из бд секрет с этим ключом,
        await secret_service.records.delete_one({hash_key: {"$exists": True}})
        # сообщает об этом пользователю и просит придумать ключ сложнее
        return {"message": "Likely, your key was too simple. A record with such a key already existed.\n"
                           "Your record was not created, and someone else's record with the key was deleted.\n"
                           "Please choose more complex keys."}
    else:
        # Получает секрет
        user_secret = secret.secret
        # Кодирует секрет используя ключ
        ciphertext = code_it(user_key, user_secret)

        # Установливает TTL для записи в базе данных, если ttl_seconds задано
        ttl_seconds = secret.ttl_seconds
        expiration_time = None
        if ttl_seconds is not None:
            expiration_time = datetime.utcnow() + timedelta(seconds=ttl_seconds * 3600)  # Переводит секунды в часы

        # Записывает в базу данных
        await secret_service.records.insert_one({
            hash_key: ciphertext,
            "expiration_time": expiration_time  # Добавляет поле expiration_time
        })
        return {"message": "Secret created successfully"}


@app.get("/get_secret/", response_model=dict)
async def create_secret(user_key: str, request: Request) -> dict:
    mongo_client: AsyncIOMotorClient = request.app.state.mongo_client["secret_service"]
    # Хэшируем ключ для поиска в базе данных
    hash_key = hash_it(user_key)

    # Ищем в базе данных, есть ли секрет с таким же хэшем ключа
    encrypted_data = await mongo_client.records.find_one({hash_key: {"$exists": True}})
    if encrypted_data:
        # Получаем из данных секрет
        encrypted_secret = encrypted_data.get(hash_key)
        await mongo_client.records.delete_one({hash_key: {"$exists": True}})
    else:
        # Если документ не найден, возвращаем ошибку 404
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Secret not found")

    # Декодируем секретные данные
    secret = decode_it(user_key, encrypted_secret)

    # Возвращаем результат
    return {"secret": secret}
