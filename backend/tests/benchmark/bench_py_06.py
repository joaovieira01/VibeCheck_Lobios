import requests
from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/preview")
async def preview(request: Request):
    address = request.query_params["address"]
    return requests.get(address).text
