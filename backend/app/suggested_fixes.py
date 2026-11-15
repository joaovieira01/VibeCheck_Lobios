"""Correções determinísticas e conservadoras para achados do scanner."""

from __future__ import annotations

import re
from pathlib import Path


_ASSIGNMENT = re.compile(
    r"^(?P<prefix>[ \t]*(?:(?:export\s+)?(?:const|let|var)\s+)?"
    r"(?P<name>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*=\s*)"
    r"(?P<quoted>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
    r"(?P<tail>\s*;?\s*(?:#.*|//.*)?)$"
)
_PYTHON_SQL_CALL = re.compile(
    r"^(?P<prefix>[ \t]*(?:[A-Za-z_]\w*\.)+execute\(\s*)"
    r"f(?P<quote>['\"])(?P<sql>.*?)(?P=quote)"
    r"(?P<suffix>\s*\)\s*;?\s*(?:#.*)?)$"
)
_JAVASCRIPT_SQL_CALL = re.compile(
    r"^(?P<prefix>[ \t]*(?P<callee>(?:[A-Za-z_$][\w$]*\.)+"
    r"[A-Za-z_$][\w$]*)\s*\(\s*)`(?P<sql>[^`]*)`"
    r"(?P<suffix>\s*\)\s*;?\s*(?://.*)?)$"
)
_INTERPOLATION = re.compile(r"\{([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\}")
_JS_INTERPOLATION = re.compile(r"\$\{([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\}")


def _is_python(filename: str) -> bool:
    return filename.lower().endswith(".py")


def _is_javascript(filename: str) -> bool:
    return Path(filename).suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


def _environment_name(name: str) -> str:
    name = name.rsplit(".", 1)[-1]
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()


def _environment_reference(filename: str, name: str, quote: str = '"') -> str:
    if _is_python(filename):
        return f"os.environ[{quote}{name}{quote}]"
    return f"process.env.{name}"


def _fix_secret(filename: str, line: str) -> dict[str, str] | None:
    match = _ASSIGNMENT.fullmatch(line)
    if match:
        quoted = match.group("quoted")
        quote = quoted[0]
        env_name = _environment_name(match.group("name"))
        if not env_name:
            return None
        reference = _environment_reference(filename, env_name, quote)
        explanation = (
            f"Defina {env_name} no ambiente e garanta que os segredos não sejam versionados."
        )
        if _is_python(filename):
            explanation += " Importe os se necessário."
        return {
            "before": line,
            "after": f"{match.group('prefix')}{reference}{match.group('tail')}",
            "explanation": explanation,
        }

    match = re.match(
        r"^(?P<prefix>[ \t]*jwt\.sign\s*\(\s*[^,\r\n]*,\s*)"
        r"(?P<quoted>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
        r"(?P<suffix>\s*(?:,\s*[^)]*)?\)\s*;?\s*(?://.*)?)$",
        line,
        re.IGNORECASE,
    )
    if not match:
        return None
    reference = _environment_reference(filename, "JWT_SECRET", match.group("quoted")[0])
    return {
        "before": line,
        "after": f"{match.group('prefix')}{reference}{match.group('suffix')}",
        "explanation": (
            "Defina JWT_SECRET no ambiente e rotacione a chave que estava no código."
            + (" Importe os se necessário." if _is_python(filename) else "")
        ),
    }


def _fix_sql(
    filename: str, source: str, line: str
) -> dict[str, str] | None:
    if _is_python(filename):
        match = _PYTHON_SQL_CALL.fullmatch(line)
        if not match:
            return None
        if re.search(r"\b(?:import\s+sqlite3|from\s+sqlite3\s+import)\b", source):
            placeholder = "?"
        elif re.search(r"\b(?:import\s+(?:psycopg|pymysql|MySQLdb)|"
                       r"from\s+(?:psycopg|pymysql|MySQLdb)\b)", source):
            placeholder = "%s"
        else:
            return None
        sql = match.group("sql")
        values = _INTERPOLATION.findall(sql)
        if not values or sql.count("{") != len(values) or sql.count("}") != len(values):
            return None
        safe_sql = _INTERPOLATION.sub(placeholder, sql)
        parameters = ", ".join(values)
        if len(values) == 1:
            parameters += ","
        after = (
            f"{match.group('prefix')}{match.group('quote')}{safe_sql}"
            f"{match.group('quote')}, ({parameters}){match.group('suffix')}"
        )
    else:
        match = _JAVASCRIPT_SQL_CALL.fullmatch(line)
        if not match:
            return None
        callee = match.group("callee")
        if callee == "knex.raw":
            driver = "knex"
        elif callee == "sequelize.query":
            driver = "sequelize"
        elif callee == "prisma.$queryRawUnsafe":
            driver = "prisma"
        elif re.search(r"""(?:from\s*|require\s*\(\s*)["']pg["']""", source):
            driver = "pg"
        elif re.search(r"""(?:from\s*|require\s*\(\s*)["']mysql2?["']""", source):
            driver = "mysql"
        else:
            return None
        sql = match.group("sql")
        values = _JS_INTERPOLATION.findall(sql)
        if not values or sql.count("${") != len(values) or sql.count("}") != len(values):
            return None
        if driver == "pg" or driver == "prisma":
            placeholder_index = 0

            def parameter_placeholder(_match: re.Match[str]) -> str:
                nonlocal placeholder_index
                placeholder_index += 1
                return f"${placeholder_index}"

            safe_sql = _JS_INTERPOLATION.sub(parameter_placeholder, sql)
        else:
            safe_sql = _JS_INTERPOLATION.sub("?", sql)
        parameters = ", ".join(values)
        if driver == "sequelize":
            binding = f"{{ replacements: [{parameters}] }}"
        elif driver == "prisma":
            binding = parameters
        else:
            binding = f"[{parameters}]"
        after = (
            f"{match.group('prefix')}`{safe_sql}`, {binding}"
            f"{match.group('suffix')}"
        )

    return {
        "before": line,
        "after": after,
        "explanation": (
            "Envie os valores como parâmetros separados do SQL. Confira se o "
            "placeholder corresponde ao driver usado."
        ),
    }


def _fix_weak_hash(filename: str, line: str) -> dict[str, str] | None:
    if _is_python(filename):
        match = re.fullmatch(
            r"(?P<indent>[ \t]*)(?P<name>[A-Za-z_]\w*)\s*=\s*"
            r"hashlib\.(?:md5|sha1)\s*\(\s*"
            r"(?P<password>[A-Za-z_]\w*\.encode\(\))\s*\)\.hexdigest\(\)"
            r"(?P<tail>\s*(?:#.*)?)",
            line,
            re.IGNORECASE,
        )
        if not match:
            return None
        salt = f"{match.group('name')}_salt"
        after = (
            f"{match.group('indent')}{salt} = __import__(\"os\").urandom(16)\n"
            f"{match.group('indent')}{match.group('name')} = "
            f"{salt}.hex() + \":\" + hashlib.scrypt("
            f"{match.group('password')}, salt={salt}, n=16384, r=8, p=1).hex()"
            f"{match.group('tail')}"
        )
        explanation = (
            "Use scrypt com salt aleatório e armazene o salt junto do hash; "
            "recupere-o para verificar a senha."
        )
    else:
        match = re.fullmatch(
            r"(?P<indent>[ \t]*(?:(?:export\s+)?(?:const|let|var)\s+)?)"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*crypto\.createHash\("
            r"(?P<quote>['\"])(?:md5|sha1)(?P=quote)\)\.update\("
            r"(?P<password>[A-Za-z_$][\w$]*)\)\.digest\("
            r"(?P=quote)hex(?P=quote)\);?",
            line,
            re.IGNORECASE,
        )
        if not match:
            return None
        salt = f"{match.group('name')}Salt"
        quote = match.group("quote")
        after_hash = (
            "`${"
            + salt
            + f".toString({quote}hex{quote})}}:"
            + "${crypto.scryptSync("
            + match.group("password")
            + ", "
            + salt
            + f", 64).toString({quote}hex{quote})}}`;"
        )
        after = (
            f"{match.group('indent')}{salt} = crypto.randomBytes(16);\n"
            f"{match.group('indent')}{match.group('name')} = {after_hash}"
        )
        explanation = (
            "Use scrypt com salt aleatório e armazene o salt junto do hash; "
            "recupere-o para verificar a senha."
        )
    return {"before": line, "after": after, "explanation": explanation}


def _fix_line(
    rule_id: str, filename: str, source: str, line: str
) -> dict[str, str] | None:
    python = _is_python(filename)
    if rule_id == "hardcoded-secret":
        return _fix_secret(filename, line)
    if rule_id == "sql-injection":
        return _fix_sql(filename, source, line)
    if rule_id == "unsafe-yaml":
        if line.count("yaml.load") != 1:
            return None
        after = re.sub(r"\byaml\.load(?=\s*\()", "yaml.safe_load", line, count=1)
        return {
            "before": line,
            "after": after,
            "explanation": "Use o carregador seguro do PyYAML para não instanciar objetos arbitrários.",
        }
    if rule_id == "debug-mode":
        pattern = re.compile(r"\bdebug\s*=\s*True\b", re.IGNORECASE)
        matches = list(pattern.finditer(line))
        if len(matches) != 1:
            return None
        after = pattern.sub(
            lambda match: match.group(0)[:-4] + ("False" if python else "false"),
            line,
            count=1,
        )
        return {
            "before": line,
            "after": after,
            "explanation": "Mantenha o modo de depuração desativado fora de testes locais controlados.",
        }
    if rule_id == "tls-disabled":
        pattern = re.compile(r"\bverify\s*=\s*False\b", re.IGNORECASE)
        if len(list(pattern.finditer(line))) != 1:
            return None
        after = pattern.sub(
            lambda match: match.group(0)[:-5] + ("True" if python else "true"),
            line,
            count=1,
        )
        return {
            "before": line,
            "after": after,
            "explanation": "Mantenha a validação do certificado TLS habilitada.",
        }
    if rule_id == "weak-random-token":
        pattern = re.compile(
            r"^(?P<prefix>[ \t]*(?:(?:const|let|var)\s+)?"
            r"[A-Za-z_$][\w$]*\s*=\s*)(?P<value>.*?)(?P<tail>\s*;?\s*(?:#.*|//.*)?)$"
        )
        match = pattern.fullmatch(line)
        if not match:
            return None
        replacement = (
            "secrets.token_urlsafe(32)" if python
            else 'crypto.randomBytes(32).toString("hex")'
        )
        return {
            "before": line,
            "after": f"{match.group('prefix')}{replacement}{match.group('tail')}",
            "explanation": (
                "Use um gerador criptograficamente seguro; importe secrets em Python "
                "ou crypto de node:crypto em Node.js."
            ),
        }
    if rule_id == "wildcard-cors":
        pattern = re.compile(
            r"(?P<prefix>\b(?:origin|origins)\s*[:=]\s*)"
            r"(?P<quote>['\"])\*(?P=quote)",
            re.IGNORECASE,
        )
        matches = list(pattern.finditer(line))
        if len(matches) != 1:
            return None
        quote = matches[0].group("quote")
        replacement = (
            f"{matches[0].group('prefix')}"
            f"{_environment_reference(filename, 'CORS_ALLOWED_ORIGIN', quote)}"
        )
        return {
            "before": line,
            "after": pattern.sub(replacement, line, count=1),
            "explanation": (
                "Configure CORS_ALLOWED_ORIGIN com uma origem confiável e não use "
                "o curinga em produção."
                + (" Importe os se necessário." if python else "")
            ),
        }
    if rule_id == "server-all-interfaces":
        pattern = re.compile(r"(?P<quote>['\"])0\.0\.0\.0(?P=quote)")
        if len(list(pattern.finditer(line))) != 1:
            return None
        return {
            "before": line,
            "after": pattern.sub(lambda match: f"{match.group('quote')}127.0.0.1{match.group('quote')}", line, count=1),
            "explanation": "Limite o servidor de desenvolvimento à interface local.",
        }
    if rule_id == "weak-password-hash":
        return _fix_weak_hash(filename, line)
    if rule_id == "dynamic-eval":
        if len(list(re.finditer(r"\beval(?=\s*\()", line))) != 1:
            return None
        replacement = "ast.literal_eval" if python else "JSON.parse"
        explanation = "Faça parsing apenas de dados."
        if python:
            explanation += " Importe ast em Python;"
        explanation += " literal_eval aceita literais Python; JSON.parse aceita somente JSON válido."
        return {
            "before": line,
            "after": re.sub(r"\beval(?=\s*\()", replacement, line, count=1),
            "explanation": explanation,
        }
    return None


def suggested_fixes_for(
    rule_id: str, filename: str, source: str, locations: list[int]
) -> list[dict[str, str]] | None:
    """Gera uma correção por localização ou omite o campo se alguma for incerta."""
    if not (_is_python(filename) or _is_javascript(filename)):
        return None
    lines = re.split(r"\r?\n", source)
    fixes: list[dict[str, str]] = []
    for location in locations:
        if location < 1 or location > len(lines):
            return None
        fix = _fix_line(rule_id, filename, source, lines[location - 1])
        if fix is None:
            return None
        fixes.append(fix)
    return fixes or None
