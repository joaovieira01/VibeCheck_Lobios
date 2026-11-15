from pathlib import Path
from fastapi import FastAPI, Request

app = FastAPI()
ROOT = Path("/srv/reports")

@app.get("/reports")
def read_report(request: Request):
    return open(str(ROOT) + request.query_params["name"], "rb").read()
