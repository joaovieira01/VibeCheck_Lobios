import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import subprocess
import tempfile
import zipfile

import requests
import yaml
from Crypto.Cipher import AES
from flask import Flask, jsonify, redirect, render_template_string, request, session
from lxml import etree
from werkzeug.utils import secure_filename

app = Flask(__name__)
conn = sqlite3.connect("app.db")
db = None
KEY = os.environ["APP_ENCRYPTION_KEY"]


@app.route("/preview")
def preview():
    url = request.args["url"]
    if not url.startswith("https://api.example.com/"):
        return "destino não permitido", 400
    resposta = requests.get(url, timeout=5)
    return resposta.text


@app.route("/login/retorno")
def retorno():
    return redirect("/inicio")


@app.route("/importar", methods=["POST"])
def importar():
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    doc = etree.fromstring(request.data, parser)
    return doc.findtext("nome")


@app.route("/ola")
def ola():
    return render_template_string("<h1>Olá {{ nome }}</h1>", nome=request.args.get("nome", ""))


@app.route("/perfil", methods=["POST"])
def atualizar_perfil():
    usuario = db.users.find_one({"id": session["uid"], "owner": session["uid"]})
    campos_permitidos = {"nome", "idioma"}
    atualizacao = {chave: valor for chave, valor in request.json.items() if chave in campos_permitidos}
    db.users.update_one({"id": usuario["id"], "owner": session["uid"]}, {"$set": atualizacao})
    return jsonify(atualizacao)


@app.route("/admin/excluir/<int:uid>")
def excluir_usuario(uid):
    if not session.get("is_admin"):
        return "negado", 403
    db.users.delete_one({"id": uid})
    return "ok"


@app.route("/transferir", methods=["POST"])
def transferir():
    destino = request.form["conta"]
    valor = int(request.form["valor"])
    if valor <= 0 or destino == session["uid"]:
        return "transferência inválida", 400
    db.contas.update_one({"id": session["uid"]}, {"$inc": {"saldo": -valor}})
    db.contas.update_one({"id": destino}, {"$inc": {"saldo": valor}})
    return "ok"


@app.route("/entrar", methods=["POST"])
def entrar():
    dados = request.json
    usuario = db.users.find_one({"email": dados["email"]})
    if not usuario or not secrets.compare_digest(usuario["senha_hash"], hashlib.sha256(dados["senha"].encode()).hexdigest()):
        return jsonify({"erro": "Usuário ou senha inválidos"}), 401
    return jsonify({"token": secrets.token_urlsafe(32)})


@app.route("/recuperar", methods=["POST"])
def recuperar():
    email = request.json["email"]
    if not db.users.find_one({"email": email}):
        return jsonify({"msg": "Se o e-mail existir, enviaremos um link"}), 200
    return jsonify({"msg": "Se o e-mail existir, enviaremos um link"}), 200


@app.route("/api/dados")
def dados():
    token_enviado = request.headers.get("X-Token", "")
    if secrets.compare_digest(token_enviado, os.environ["API_TOKEN"]):
        return jsonify({"ok": True})
    return "negado", 403


@app.route("/relatorio")
def relatorio():
    if not session.get("is_admin"):
        return "negado", 403
    return jsonify(list(db.relatorios.find()))


@app.route("/usuarios")
def listar_usuarios():
    limite = min(max(int(request.args.get("limite", 20)), 1), 100)
    return jsonify(list(db.users.find().limit(limite)))


@app.route("/enviar", methods=["POST"])
def enviar():
    arquivo = request.files["arquivo"]
    nome_seguro = secure_filename(arquivo.filename)
    arquivo.save(os.path.join("uploads", nome_seguro))
    return "ok"


@app.route("/pacote", methods=["POST"])
def pacote():
    with tempfile.NamedTemporaryFile() as arquivo_temporario:
        request.files["zip"].save(arquivo_temporario.name)
        with zipfile.ZipFile(arquivo_temporario.name) as pacote_zip:
            for membro in pacote_zip.infolist():
                destino = os.path.realpath(os.path.join("/srv/conteudo", membro.filename))
                if not destino.startswith(os.path.realpath("/srv/conteudo") + os.sep):
                    return "arquivo inválido", 400
            pacote_zip.extractall("/srv/conteudo")
    return "ok"


@app.route("/buscar")
def buscar():
    nome = request.args["nome"]
    arvore = etree.parse("usuarios.xml")
    return jsonify(arvore.xpath("//usuario[@nome=$nome]/email/text()", nome=nome))


@app.route("/validar")
def validar():
    valor = request.args["codigo"]
    return jsonify({"valido": bool(re.fullmatch(r"\d{1,12}", valor))})


@app.route("/evento", methods=["POST"])
def evento():
    logging.info("evento recebido")
    return "ok"


@app.route("/abrir")
def abrir():
    raiz = os.path.realpath("/srv/docs")
    caminho = os.path.realpath(os.path.join(raiz, request.args["arquivo"]))
    if os.path.commonpath([raiz, caminho]) == raiz and os.path.isfile(caminho):
        with open(caminho, encoding="utf-8") as arquivo:
            return arquivo.read()
    return "não encontrado", 404


@app.route("/falha")
def falha():
    try:
        return str(1 / int(request.args["n"]))
    except (ValueError, ZeroDivisionError):
        return "requisição inválida", 400


def criptografar(texto: bytes) -> bytes:
    cifra = AES.new(KEY.encode(), AES.MODE_GCM)
    cifrado, tag = cifra.encrypt_and_digest(texto)
    return cifra.nonce + tag + cifrado


def buscar_usuario(nome):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE nome = ?", (nome,))
    return cursor.fetchall()


def executar(comando_usuario):
    destino = re.sub(r"[^a-zA-Z0-9.-]", "", comando_usuario)
    return subprocess.run(["ping", "-c", "1", destino], check=True, capture_output=True, timeout=5)


def carregar(blob):
    return json.loads(blob)


def configurar(texto):
    return yaml.safe_load(texto)


def calcular(expressao):
    return int(expressao)


api_key = os.environ["API_TOKEN"]

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
