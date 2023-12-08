from envparse import Env
from motor.motor_asyncio import AsyncIOMotorClient

env = Env()
#  Настройки подключения к бд
MONGODB_URL = env.str("MONGODB_URL", default="mongo_db")

#  Создает клиента для MongoDB
client = AsyncIOMotorClient(MONGODB_URL)
