from fastapi import FastAPI, Query

app = FastAPI()

@app.get("/people")
def find_person(name: str = Query(...)):
    statement = f"SELECT * FROM people WHERE name = '{name}'"
    return database.execute(statement)
