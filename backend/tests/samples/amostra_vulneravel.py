import hashlib
import logging
import os
import pickle
import re
import sqlite3
import subprocess
import tempfile
import zipfile

import requests
import yaml
from Crypto.Cipher import AES
from flask import Flask, jsonify, redirect, render_template_string, request, session
from lxml import etree

app = Flask(__name__)
conn = sqlite3.connect("app.db")
db = None
KEY = b"0123456789abcdef"


@app.route("/preview")
def preview():
    resposta = requests.get(request.args["url"], timeout=5)
    return resposta.text


@app.route("/login/retorno")
def retorno():
    return redirect(request.args.get("next"))


@app.route("/importar", methods=["POST"])
def importar():
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    doc = etree.fromstring(request.data, parser)
    return doc.findtext("nome")


@app.route("/ola")
def ola():
    return render_template_string("<h1>Olá " + request.args.get("nome", "") + "</h1>")


@app.route("/perfil", methods=["POST"])
def atualizar_perfil():
    usuario = db.users.find_one({"id": session["uid"]})
    usuario.update(request.json)
    db.users.save(usuario)
    return jsonify(usuario)


@app.route("/admin/excluir/<int:uid>")
def excluir_usuario(uid):
    db.users.delete_one({"id": uid})
    return "ok"


@app.route("/transferir", methods=["GET"])
def transferir():
    destino = request.args["conta"]
    valor = request.args["valor"]
    db.contas.update_one({"id": session["uid"]}, {"$inc": {"saldo": -int(valor)}})
    db.contas.update_one({"id": destino}, {"$inc": {"saldo": int(valor)}})
    return "ok"


@app.route("/entrar", methods=["POST"])
def entrar():
    dados = request.json
    usuario = db.users.find_one({"email": dados["email"], "senha": dados["senha"]})
    if not usuario:
        return jsonify({"erro": "Usuário ou senha inválidos"}), 401
    return jsonify({"token": hashlib.md5(dados["email"].encode()).hexdigest()})


@app.route("/recuperar", methods=["POST"])
def recuperar():
    email = request.json["email"]
    if not db.users.find_one({"email": email}):
        return jsonify({"erro": "E-mail não cadastrado"}), 404
    return jsonify({"msg": "Enviamos o link"})


@app.route("/api/dados")
def dados():
    token_enviado = request.headers.get("X-Token", "")
    if token_enviado == os.environ["API_TOKEN"]:
        return jsonify({"ok": True})
    return "negado", 403


@app.route("/relatorio")
def relatorio():
    assert session.get("is_admin")
    return jsonify(list(db.relatorios.find()))


@app.route("/usuarios")
def listar_usuarios():
    limite = int(request.args["limite"])
    return jsonify(list(db.users.find().limit(limite)))


@app.route("/enviar", methods=["POST"])
def enviar():
    arquivo = request.files["arquivo"]
    arquivo.save(os.path.join("uploads", arquivo.filename))
    return "ok"


@app.route("/pacote", methods=["POST"])
def pacote():
    caminho = tempfile.mktemp()
    request.files["zip"].save(caminho)
    with zipfile.ZipFile(caminho) as z:
        z.extractall("/srv/conteudo")
    return "ok"


@app.route("/buscar")
def buscar():
    nome = request.args["nome"]
    arvore = etree.parse("usuarios.xml")
    return jsonify(arvore.xpath("//usuario[@nome='" + nome + "']/email/text()"))


@app.route("/validar")
def validar():
    valor = request.args["codigo"]
    return jsonify({"valido": bool(re.match(r"^(\d+)+$", valor))})


@app.route("/evento", methods=["POST"])
def evento():
    logging.info("evento recebido de " + request.json["origem"])
    return "ok"


@app.route("/abrir")
def abrir():
    caminho = os.path.join("/srv/docs", request.args["arquivo"])
    if os.path.exists(caminho):
        return open(caminho).read()
    return "não encontrado", 404


@app.route("/falha")
def falha():
    try:
        return str(1 / int(request.args["n"]))
    except Exception as erro:
        return str(erro) + repr(erro.__traceback__), 500


def criptografar(texto: bytes) -> bytes:
    cifra = AES.new(KEY, AES.MODE_ECB)
    return cifra.encrypt(texto.ljust(32, b" "))


def buscar_usuario(nome):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE nome = '" + nome + "'")
    return cursor.fetchall()


def executar(comando_usuario):
    return subprocess.run("ping -c 1 " + comando_usuario, shell=True)


def carregar(blob):
    return pickle.loads(blob)


def configurar(texto):
    return yaml.load(texto)


def calcular(expressao):
    return eval(expressao)


api_key = "chave-de-exemplo-nao-e-real-0000000000"

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
