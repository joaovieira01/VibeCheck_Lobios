from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
from scanner import analisar_codigo

app = FastAPI()


class CodigoRequest(BaseModel):
    codigo: str


@app.get("/")
def inicio():
    return {
        "mensagem": "Lobios API funcionando!"
    }


@app.post("/scan")
def scan_codigo(request: CodigoRequest):
    vulnerabilidades = analisar_codigo(request.codigo)

    return {
        "total": len(vulnerabilidades),
        "vulnerabilidades": vulnerabilidades
    }


@app.post("/scan-file")
async def scan_file(file: UploadFile = File(...)):
    conteudo = await file.read()

    codigo = conteudo.decode("utf-8")

    vulnerabilidades = analisar_codigo(codigo)

    return {
        "arquivo": file.filename,
        "total": len(vulnerabilidades),
        "vulnerabilidades": vulnerabilidades
    }
