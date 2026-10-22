"""Primitivas de segurança, só com a biblioteca padrão.

- Senhas: scrypt com salt aleatório; parâmetros ficam no próprio hash, então dá
  para aumentar o custo no futuro sem invalidar hashes antigos.
- Tokens (sessão e recuperação de senha): 256 bits aleatórios. O banco guarda só
  o SHA-256, então um vazamento do banco não entrega tokens utilizáveis.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# N=2**15, r=8 usa ~32 MiB por hash. Aumente (N=2**17 é o recomendado pela OWASP
# para o mínimo) se o servidor tiver memória e a latência de login permitir.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=_KEY_BYTES,
        maxmem=256 * n * r * p,
    )


def hash_password(password: str, *, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P) -> str:
    salt = secrets.token_bytes(_SALT_BYTES)
    key = _scrypt(password, salt, n, r, p)
    return f"scrypt${n}${r}${p}${_b64(salt)}${_b64(key)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, key_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(key_b64)
        actual = _scrypt(password, salt, int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


_dummy_hash: str | None = None


def burn_password_check(password: str) -> None:
    """Gasta o mesmo tempo de uma verificação real (e-mail inexistente no login).

    Evita que o tempo de resposta revele se o e-mail está cadastrado.
    """
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("senha-inexistente")
    verify_password(password, _dummy_hash)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
