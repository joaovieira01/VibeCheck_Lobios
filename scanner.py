import re


def analisar_codigo(codigo: str):
    vulnerabilidades = []

    # 1. Detectar eval()
    if re.search(r"\beval\s*\(", codigo):
        vulnerabilidades.append({
            "tipo": "Uso de eval()",
            "severidade": "Alta",
            "descricao": "eval() pode executar código não confiável.",
            "recomendacao": "Evite eval() e utilize alternativas seguras."
        })

    # 2. Detectar senhas expostas
    padrao_senha = r"(?i)(password|senha|passwd)\s*=\s*['\"][^'\"]+['\"]"

    if re.search(padrao_senha, codigo):
        vulnerabilidades.append({
            "tipo": "Senha exposta no código",
            "severidade": "Alta",
            "descricao": "Uma senha parece estar escrita diretamente no código.",
            "recomendacao": "Utilize variáveis de ambiente ou um gerenciador de segredos."
        })

    # 3. Detectar possíveis SQL Injection
    if re.search(r"(?i)(SELECT|INSERT|UPDATE|DELETE).*(\+|f['\"])", codigo):
        vulnerabilidades.append({
            "tipo": "Possível SQL Injection",
            "severidade": "Alta",
            "descricao": "Foi encontrada uma possível montagem insegura de consulta SQL.",
            "recomendacao": "Utilize consultas parametrizadas."
        })

    return vulnerabilidades
