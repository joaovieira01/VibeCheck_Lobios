from fastapi import FastAPI, Depends

app = FastAPI()

@app.get("/private")
def private_report(user=Depends(require_user)):
    return {"owner": user.id, "items": []}
