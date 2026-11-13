# VibeCheck

Ferramenta de auditoria de segurança para código gerado por IA e escrito com pressa. Você envia um arquivo ou cola um trecho, e o VibeCheck aponta padrões de risco com a linha exata, o impacto provável, as referências CWE e OWASP e uma recomendação de correção.

**Demo:** https://vibechecklobios.vercel.app/

**Status:** MVP em desenvolvimento ativo. As funcionalidades e os formatos de resposta ainda podem mudar.

> **Escopo.** A análise é feita por regras heurísticas, linha a linha, mapeadas para o OWASP Top 10:2025. O VibeCheck serve como apoio à revisão e à conscientização. Ele não substitui uma auditoria de segurança, um teste de intrusão nem uma verificação de conformidade.

## Sumário

- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Início rápido](#início-rápido)
- [Execução manual](#execução-manual)
- [Uso](#uso)
- [Configuração](#configuração)
- [Análise com IA (opcional)](#análise-com-ia-opcional)
- [Revisão automática de Pull Requests](#revisão-automática-de-pull-requests)
- [Testes](#testes)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Segurança](#segurança)
- [Limitações e roadmap](#limitações-e-roadmap)
- [Referências](#referências)
- [Contribuindo](#contribuindo)

## Funcionalidades

**Análise de código**
- Entrada por upload de arquivo ou colagem de trecho.
- 41 regras, com severidade, CWE e categoria OWASP Top 10:2025 (A01 a A10).
- Cada achado informa linha, evidência, impacto, recomendação e forma de prevenção.
- Relatório em PDF gerado no navegador.

**Contas e histórico**
- Cadastro e login pela API.
- Histórico de análises persistido no banco.
- Modo local: sem `VITE_API_URL`, a análise roda no navegador e o código não é enviado a nenhum servidor.

**Automação**
- Revisão de Pull Requests no GitHub Actions, com comentários nas linhas novas.
- Camada opcional de IA no backend para triar achados e sugerir revisões (desligada por padrão).

## Arquitetura

```
Frontend (React + Vite)  ──HTTP /api──►  Backend (FastAPI)  ───►  MySQL 8.4
        :5173                                 :8000
```

| Camada | Tecnologia |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | FastAPI (Python), autenticação e motor de análise |
| Banco de dados | MySQL 8.4 (SQLite opcional para testes locais) |
| Infraestrutura | Docker Compose |
| CI | GitHub Actions |
| Testes | pytest (backend) e Vitest (frontend) |

As regras ficam em um único arquivo, `backend/app/rules.json`, e são usadas pelo scanner em Python e pelo scanner em TypeScript. O frontend consome uma cópia gerada com `npm run sync:rules` (em `frontend/`), e um teste verifica que ela é idêntica ao original.

## Início rápido

Pré-requisitos: Git e Docker Desktop.

```powershell
git clone https://github.com/joaovieira01/VibeCheck_Lobios.git
cd VibeCheck_Lobios

Copy-Item .env.example .env
# Edite o .env e defina senhas próprias antes de continuar.

docker compose up --build
```

| Serviço | Endereço |
|---|---|
| Frontend | http://localhost:5173 |
| API | http://localhost:8000 |
| Documentação da API | http://localhost:8000/docs |
| MySQL | localhost:3306 |

Para subir somente o banco durante o desenvolvimento: `docker compose up -d mysql`.

## Execução manual

Pré-requisitos: Python 3.12 e Node.js 22 (as versões usadas nos contêineres; o Vite 7 não funciona em versões antigas do Node), além de MySQL 8.4 ou SQLite para testes.

**Banco de dados.** Execute `database/schema.sql` no MySQL, trocando `CHANGE_THIS_PASSWORD` por uma senha forte, ou use apenas o contêiner do MySQL.

**Backend**

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
uvicorn app.main:create_app --factory --reload
```

O backend lê o `.env` da raiz do repositório. Para testar com SQLite, defina `VIBECHECK_DB_ENGINE=sqlite` e `VIBECHECK_DB_PATH=data/vibecheck.db`.

**Frontend**

```powershell
cd frontend
npm ci
Copy-Item .env.local.example .env.local
npm run dev
```

Use `npm ci` para instalar exatamente as versões do `package-lock.json`.

## Uso

**Aplicação web.** Abra o frontend, escolha um arquivo ou cole um trecho de código e inicie a análise. O resultado lista os achados por severidade, com a linha, a evidência e a recomendação. O relatório pode ser exportado em PDF. Com a API configurada, cada análise fica salva no histórico da conta.

**Limites.** Cada análise aceita até 1 MB de código, as linhas são truncadas em 1.000 caracteres e há um tempo máximo de execução. Acima disso, a API responde com erro explicando o motivo.

**Formato de um achado.** Exemplo de resultado para `yaml.load(texto)` em um arquivo Python:

```json
{
  "id": "unsafe-yaml",
  "title": "Desserialização YAML potencialmente insegura",
  "severity": "Alta",
  "cwe": "CWE-502",
  "owaspId": "A08",
  "owaspName": "Falhas de integridade de software ou dados",
  "description": "yaml.load() pode instanciar objetos quando não usa um loader seguro.",
  "recommendation": "Use yaml.safe_load() ou especifique explicitamente SafeLoader.",
  "impact": "Configurações manipuladas podem causar execução de código ou efeitos inesperados durante o carregamento.",
  "prevention": "Prefira loaders seguros por padrão e teste a rejeição de tags e objetos não permitidos.",
  "locations": [4],
  "evidence": ["return yaml.load(texto)"]
}
```

**Linha de comando.** Para analisar um arquivo local sem subir a aplicação:

```powershell
cd backend
python scripts/scan_file.py caminho\para\arquivo.py
```

A documentação interativa dos endpoints fica em `/docs` na API.

## Configuração

| Variável | Descrição | Exemplo |
|---|---|---|
| `MYSQL_ROOT_PASSWORD` | Senha do root do MySQL no Docker Compose | defina uma senha forte |
| `VIBECHECK_DB_ENGINE` | Banco usado pelo backend | `mysql` ou `sqlite` |
| `VIBECHECK_DB_HOST`, `VIBECHECK_DB_PORT` | Endereço do MySQL | `127.0.0.1`, `3306` |
| `VIBECHECK_DB_NAME` | Nome do banco | `vibecheck` |
| `VIBECHECK_DB_USER` | Usuário exclusivo da aplicação | `vibecheck_user` |
| `VIBECHECK_DB_PASSWORD` | Senha do banco | defina uma senha forte |
| `VIBECHECK_DB_PATH` | Arquivo do banco quando o motor é SQLite | `data/vibecheck.db` |
| `VIBECHECK_CORS_ORIGINS` | Origens permitidas no CORS | `http://localhost:5173` |
| `VIBECHECK_FRONTEND_URL` | URL do frontend | `http://localhost:5173` |
| `VIBECHECK_RATE_LIMIT` | Limite de requisições | `true` |
| `VIBECHECK_SEED_DEMO_USER` | Cria usuário de demonstração | `false` |
| `VITE_API_URL` | URL da API usada pelo frontend | `http://localhost:8000` |

Sem `VITE_API_URL`, o frontend funciona em modo local: cadastro, análise e histórico ficam no navegador.

As variáveis da camada de IA estão na seção seguinte.

## Análise com IA (opcional)

A análise por regras é o comportamento padrão. A camada de IA fica desligada, não depende de fornecedor e usa o formato de chat completions compatível com a API da OpenAI. Quando ativada, ela pode:

- **Triar** os achados das regras, classificando cada um como confirmado, falso positivo ou incerto. A triagem é anexada ao achado e nunca o remove da lista. Achados de severidade crítica e credenciais fixas só recebem veredito de descarte com confiança alta.
- **Revisar funções de risco** e propor achados adicionais, sempre separados dos achados das regras e identificados como sugestões da IA. Exige `AI_DISCOVERY=true`.

Antes de enviar um trecho ao provedor, o backend mascara segredos e credenciais e trata o código como dado, não como instrução. Falhas do provedor (timeout, limite de uso, resposta inválida) não interrompem a análise: o resultado das regras é devolvido com o status de IA indisponível.

Configure por variáveis de ambiente, no `.env` local, que nunca deve ser commitado:

```dotenv
AI_ENABLED=true
AI_BASE_URL=https://provedor.example/v1
AI_API_KEY=chave-do-provedor
AI_MODEL=id-do-modelo
AI_TIMEOUT_SECONDS=20
AI_MAX_CALLS_PER_SCAN=10
AI_CONCURRENCY=2
AI_DISCOVERY=false
```

Exemplos de provedores. Confirme endereço e modelo na documentação atual de cada um antes de usar:

| Provedor | `AI_BASE_URL` | `AI_MODEL` |
|---|---|---|
| Google Gemini (endpoint compatível) | `https://generativelanguage.googleapis.com/v1beta/openai/` | `gemini-3.8-flash` |
| OpenRouter | `https://openrouter.ai/api/v1` | conforme o catálogo do provedor |
| Ollama (local) | `http://localhost:11434/v1` | qualquer modelo instalado |

O endereço precisa usar HTTPS, exceto `localhost` e `127.0.0.1`. A chave vai em `AI_API_KEY`, nunca na URL.

**Privacidade.** O código analisado é enviado ao endpoint configurado. Planos gratuitos de alguns provedores podem usar esse conteúdo para treinar ou melhorar seus serviços. Leia os termos do provedor e não envie código confidencial, segredos ou dados pessoais sem autorização. Para manter tudo na própria máquina, use um modelo local.

Para experimentar pela linha de comando:

```powershell
cd backend
python scripts/scan_file.py caminho\para\arquivo.py        # somente regras
python scripts/scan_file.py caminho\para\arquivo.py --ai   # com IA, se configurada
```

O backend carrega o `.env` da raiz na inicialização. O `scan_file.py`, por outro lado, lê apenas as variáveis do ambiente do processo, então defina as variáveis `AI_*` na sessão do terminal antes de usar `--ai`. No Docker Compose, as variáveis `AI_*` precisam ser repassadas ao serviço `backend` no `docker-compose.yml`, porque o arquivo atual não as inclui.

A IA não é usada pelo modo local do frontend nem, por enquanto, pela revisão de Pull Requests.

## Revisão automática de Pull Requests

O workflow `.github/workflows/vibecheck-pr-review.yml` roda o scanner nos arquivos alterados de cada Pull Request e comenta nas linhas novas que tiverem achados.

- Dispara quando o PR é aberto, reaberto, recebe novos commits ou sai do modo rascunho.
- Lê os arquivos pela API do GitHub, com limites de tamanho e de tempo.
- Faz checkout apenas da revisão base confiável e **nunca executa o código do PR**.
- Usa o token padrão com permissões mínimas: `contents: read` e `pull-requests: write`.
- Não exige segredos adicionais.
- Os comentários explicam a correção, mas não alteram o código. O resultado é informativo e não bloqueia o merge.

## Testes

```powershell
# Backend
cd backend
python -m pytest

# Frontend
cd frontend
npm test
npm run build

# Métricas do scanner nas amostras internas (recall e falsos positivos)
cd backend
python scripts/metrics.py
```

As amostras e o gabarito usados nas métricas estão em `backend/tests/samples/`. Os testes que envolvem IA usam um provedor falso e bloqueiam acesso à rede.

## Estrutura do repositório

```
.
├── backend/               API FastAPI, autenticação e scanner
│   ├── app/               código da aplicação (inclui app/ai/)
│   ├── scripts/           revisão de PRs, métricas e scan_file.py
│   └── tests/             testes, corpus golden e amostras
├── frontend/              React + TypeScript + Vite
├── database/schema.sql    criação do banco e do usuário MySQL
├── docs/PROGRESS.md       histórico de evolução e métricas
├── .github/workflows/     revisão automática de Pull Requests
├── docker-compose.yml     MySQL, backend e frontend
└── .env.example           exemplo de configuração, sem credenciais reais
```

## Segurança

- Nunca commite arquivos `.env` nem chaves de API.
- Troque todas as senhas de exemplo.
- Não habilite `VIBECHECK_SEED_DEMO_USER` em ambientes expostos.
- Use uma conta MySQL exclusiva da aplicação, sem privilégios de administrador.
- O `docker-compose.yml` expõe o MySQL na porta 3306 e usa `--reload`: é uma configuração de desenvolvimento. Em outros ambientes, restrinja o acesso (por exemplo, `127.0.0.1:3306:3306`) e use um servidor de produção.
- O limitador de requisições é em memória. Em mais de uma instância, use um limitador compartilhado.

## Limitações e roadmap

**Limitações conhecidas**
- As regras analisam uma linha por vez, com algum contexto de função. Elas não acompanham o fluxo de dados entre arquivos, e wrappers próprios, sanitizadores customizados e construções multilinha complexas podem escapar.
- Nas amostras internas o scanner detecta todos os itens esperados. Em amostras escritas de forma independente, a cobertura foi menor (cerca de 60% na última medição, com poucos casos), o que mostra o limite de uma abordagem baseada em regex.
- A categoria A06 (design inseguro) depende de decisões de arquitetura e exige revisão manual.
- A análise de dependências aponta versões não fixadas, mas não consulta bases de vulnerabilidades conhecidas.
- As metas de taxa de falsos positivos e de tempo de análise por repositório ainda não foram medidas em repositórios reais.

**Próximos passos**
- [ ] Tela de recuperação de senha no frontend (os endpoints do backend já existem e exigem SMTP).
- [ ] IA na revisão de Pull Requests e na interface.
- [ ] Sugestão de correção em código.
- [ ] Integração com GitLab e Bitbucket.
- [ ] Análise com contexto de fluxo de dados (motor SAST de código aberto).
- [ ] Medição de falsos positivos e de desempenho em repositórios reais.
- [ ] Configuração de deploy de produção para backend e banco.

## Referências

- OWASP Top 10: https://owasp.org/Top10/
- Common Weakness Enumeration (CWE): https://cwe.mitre.org/

## Contribuindo

A branch `development` recebe as mudanças em andamento, e a `main` guarda versões estáveis.

1. Crie uma branch a partir da `development`, por exemplo `feat/nome-da-melhoria` ou `refactor/nome-da-area`.
2. Faça commits pequenos, com mensagens que descrevam a mudança.
3. Antes de abrir o Pull Request, rode `python -m pytest` no backend e `npm test` e `npm run build` no frontend. Para mudanças nas regras, rode também `python scripts/metrics.py` e confira que os números não pioraram.
4. Abra o Pull Request para a `development`, descrevendo o que mudou e como testar.

Ao alterar `rules.json`, regenere a cópia usada pelo frontend com `npm run sync:rules` (em `frontend/`) e inclua a mudança no commit.

## Autoria

Desenvolvido por João Vieira ([@joaovieira01](https://github.com/joaovieira01)) e colaboradores.
