# VibeCheck — backend

API FastAPI para o [frontend do VibeCheck](../VibeCheck_Lobios-frontend). Faz a análise
estática de segurança no servidor, com **as mesmas 19 regras** do `scanner.ts` do frontend
(+ a regra de manifestos de dependência), e acrescenta contas de usuário, sessões,
recuperação de senha e histórico persistente por usuário.

O formato JSON é idêntico às interfaces de `src/types.ts` (`Analysis`, `Finding`), então o
frontend troca o analisador local pelo HTTP sem mudar telas nem o relatório PDF.

## Executar

Requer Python 3.11+.

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest                                                   # rode antes de tudo
uvicorn app.main:app --reload                             # http://localhost:8000
```

Documentação interativa: http://localhost:8000/docs

No frontend, crie `.env.local` com `VITE_API_URL=http://localhost:8000` e rode `npm run dev`.
Sem essa variável o frontend continua funcionando 100% local, como antes.

## Deploy no Vercel

O módulo `app.main` exporta a instância FastAPI `app` exigida pelo runtime do
Vercel. Configure `VIBECHECK_DB_ENGINE=mysql` e as variáveis
`VIBECHECK_DB_HOST`, `VIBECHECK_DB_PORT`, `VIBECHECK_DB_NAME`,
`VIBECHECK_DB_USER` e `VIBECHECK_DB_PASSWORD` para usar um banco MySQL
persistente. O SQLite local não deve ser usado para dados de produção em funções
serverless, pois o armazenamento local não é persistente entre execuções.

Em desenvolvimento, para entrar com a conta que a tela de login já exibe:
`VIBECHECK_SEED_DEMO_USER=true` cria `demo@vibecheck.dev` / `vibecheck2026`.
**É uma credencial pública; nunca ligue isso em ambiente exposto.**

Docker: `docker build -t vibecheck-api . && docker run -p 8000:8000 -v vibecheck-data:/srv/data vibecheck-api`

## Rotas

| Método | Rota | Auth | Descrição |
|---|---|---|---|
| GET | `/api/health` | — | Saúde e nº de regras |
| GET | `/api/rules` | — | Metadados das regras |
| POST | `/api/auth/register` | — | `{email, password}` → `{token, user}` (201) |
| POST | `/api/auth/login` | — | `{email, password}` → `{token, user}` |
| POST | `/api/auth/logout` | Bearer | Encerra a sessão atual (204) |
| GET | `/api/auth/me` | Bearer | Usuário da sessão |
| POST | `/api/auth/password-reset` | — | `{email}` → 202, **mesma resposta exista a conta ou não** |
| POST | `/api/auth/password-reset/confirm` | — | `{token, newPassword}` → 204; encerra todas as sessões |
| POST | `/api/analyses` | Bearer | `{filename, source}` → `Analysis` (201) e grava no histórico |
| GET | `/api/analyses` | Bearer | Histórico (até 20, mais recentes primeiro) |
| GET | `/api/analyses/{id}` | Bearer | Uma análise (só se for do usuário) |
| DELETE | `/api/analyses` | Bearer | Limpa o histórico do usuário (204) |

Erros vêm como `{"detail": "mensagem em português"}`, que é o que o frontend exibe.

## Configuração

Variáveis de ambiente (todas opcionais; veja `.env.example`):

| Variável | Padrão | Para quê |
|---|---|---|
| `VIBECHECK_DB_PATH` | `data/vibecheck.db` | Arquivo SQLite |
| `VIBECHECK_CORS_ORIGINS` | `localhost:5173,127.0.0.1:5173` | Origens do frontend (CORS) |
| `VIBECHECK_FRONTEND_URL` | `http://localhost:5173` | Base do link de recuperação |
| `VIBECHECK_SMTP_HOST/PORT/USER/PASSWORD/FROM/STARTTLS` | — | E-mail de recuperação |
| `VIBECHECK_SESSION_TTL_HOURS` | 168 | Validade da sessão |
| `VIBECHECK_RESET_TTL_MINUTES` | 30 | Validade do link de recuperação |
| `VIBECHECK_MAX_SOURCE_BYTES` | 1000000 | Limite do código (bytes UTF-8) |
| `VIBECHECK_MAX_LINE_CHARS` | 1000 | Truncamento de linha antes das regex |
| `VIBECHECK_SCAN_TIMEOUT_SECONDS` | 10 | Orçamento de tempo por análise |
| `VIBECHECK_RATE_LIMIT` | true | Limites de taxa |

**Sem `VIBECHECK_SMTP_HOST`, o link de recuperação só é impresso no log do servidor.**
Serve para desenvolver; em produção configure o SMTP (só STARTTLS, com validação de certificado).

## Estrutura

```
app/
  main.py       rotas FastAPI, CORS, limite de corpo, rate limit
  schemas.py    modelos Pydantic (JSON camelCase)
  scanner.py    porte do scanner.ts; regras em rules.json
  rules.json    regras extraídas do TypeScript (mesma regex)
  service.py    validação e montagem do resultado da análise
  auth.py       cadastro, login, sessões, recuperação de senha
  security.py   scrypt (hash de senha), tokens
  storage.py    histórico por usuário
  db.py         SQLite
  ratelimit.py  janela deslizante em memória
  mailer.py     SMTP / log
tests/          unittest (roda com pytest)
scripts/generate_golden.mjs   regenera a referência de paridade a partir do frontend
```

## Fidelidade com o frontend

`tests/golden/expected.json` guarda a saída do `scanner.ts` **original** para 19 entradas
(os exemplos do frontend, casos dos testes dele e casos de borda: CRLF, `package.json`
inválido, caminhos do Windows, acentos…). `tests/test_scanner.py::ParityTests` exige
resultado idêntico no Python. Se alterar regras no frontend, regenere (Node 22.6+):

```bash
node --experimental-strip-types scripts/generate_golden.mjs ../VibeCheck_Lobios-frontend
```

e copie as novas regras para `app/rules.json` (campos `pattern`/`safePattern`).

## Revisão de Pull Requests no GitHub

O workflow raiz `.github/workflows/aura-scanner.yml` usa este scanner para revisar
linhas adicionadas em Pull Requests e publicar comentários inline. Para ativá-lo,
mantenha o workflow no branch padrão do GitHub. Ele usa `pull_request_target` para
receber permissão de comentar em PRs de forks, mas faz checkout **somente do commit
base** e busca os arquivos alterados pela API; nenhum código do PR é executado.

O bot aceita os formatos cobertos pelo scanner, ignora arquivos acima de 1 MB e
limita a análise a 10 segundos por arquivo. Achados em linhas antigas não são
comentados. O GitHub Actions fornece `GITHUB_TOKEN` automaticamente com permissões
mínimas de leitura do repositório e escrita em comentários de PR. GitLab e Bitbucket,
além de aplicação automática de correções, permanecem fora deste primeiro adaptador.

## Segurança: decisões e limites

- **Senhas**: scrypt (N=2¹⁵, r=8, p=1) com salt por senha; parâmetros ficam no hash. Para o
  mínimo recomendado pela OWASP use N=2¹⁷ (`app/security.py`), com ~128 MiB por login.
- **Sessões**: token aleatório de 256 bits; o banco guarda só o SHA-256. Revogáveis (logout e
  redefinição de senha encerram sessões).
- **Login**: mensagem igual para e-mail inexistente e senha errada, com gasto de tempo
  equivalente. Limite de 10 tentativas/15 min por IP+e-mail.
- **Recuperação**: resposta idêntica exista a conta ou não; token de uso único, 30 min, no
  fragmento `#` da URL; e-mail enviado após a resposta.
- **Histórico isolado por usuário**; outro usuário recebe 404.
- **Entradas hostis**: algumas regex herdadas do frontend têm custo polinomial. Medido com
  1 MB hostil: sem proteção, 53 s (regex de IDOR); com linhas truncadas a 1000 caracteres,
  3,7 s no pior caso testado; o orçamento de 10 s é a segunda barreira. Consequência: **achados
  além da coluna 1000 de uma linha não são detectados** (arquivos minificados).
- Limite de corpo (6× o limite de código, por causa de escapes JSON) antes do parsing.

### Limitações conhecidas

- **O histórico guarda trechos do código (evidências, até 500 caracteres por linha)**. Quando
  uma regra acha um segredo fixo, a linha com o segredo fica no banco. O arquivo completo não é
  guardado. Proteja o banco e considere mascarar evidências sensíveis.
- Rate limit **por processo**: com vários workers/instâncias, use Redis ou o limitador do proxy.
  Atrás de proxy, rode o uvicorn com `--proxy-headers` para ver o IP real.
- O cadastro responde 409 para e-mail existente (permite descobrir se um e-mail tem conta).
- Sem verificação de e-mail, MFA, troca de senha logado ou exclusão de conta.
- SQLite atende uma instância; para mais, migre para PostgreSQL.
- As regras são heurísticas por linha: não executam o código nem substituem SAST/DAST/SCA.
