from fastapi import FastAPI


app = FastAPI()


@app.get("/ping/")
async def ping() -> dict:
    return {"Response": "pong"}

