from envparse import Env
from motor.motor_asyncio import AsyncIOMotorClient

env = Env()
#  Настройки подключения к бд
MONGODB_URL = env.str("MONGODB_URL", default="mongodb://localhost:27017/secret_service")

#  Создает клиента для MongoDB
client = AsyncIOMotorClient(MONGODB_URL)
