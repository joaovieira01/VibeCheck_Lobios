<div align="center">

# 🛡️ VibeCheck

### Encontre riscos. Entenda como agir.

Análise de segurança de código com foco em clareza: aponte padrões de risco, entenda o contexto e siga um plano de correção, tudo em uma interface simples.

[![Demo](https://img.shields.io/badge/demo-online-8b5cf6?style=for-the-badge)](https://vibecheck-website-ten.vercel.app/)
![React](https://img.shields.io/badge/React-TypeScript-61dafb?style=for-the-badge&logo=react&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Python-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-8.4-4479a1?style=for-the-badge&logo=mysql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?style=for-the-badge&logo=docker&logoColor=white)

[Demo](https://vibecheck-website-ten.vercel.app/) · [Funcionalidades](#-funcionalidades) · [Como rodar](#-como-rodar) · [Segurança](#-segurança)

</div>

---

## 📸 Visão geral

<!-- Substitua pelos seus prints. Sugestão: salve em docs/images/ -->
<div align="center">

| Landing | Análise | Relatório |
|:---:|:---:|:---:|
| ![Landing](docs/images/landing.png) | ![Análise](docs/images/analise.png) | ![Relatório](docs/images/relatorio.png) |

</div>

## 🎯 Sobre o projeto

O **VibeCheck** é uma aplicação web para auditoria de código, pensada para quem escreve (ou gera) código rápido e quer uma segunda opinião de segurança antes de publicar. Você envia um arquivo ou cola um trecho, e a plataforma:

1. **Analisa** o código com regras heurísticas;
2. **Explica** o achado com linha, impacto potencial e referências **CWE/OWASP**;
3. **Orienta** a correção com recomendações práticas;
4. **Exporta** um relatório em PDF para o próximo passo.

> ⚠️ **Transparência:** as regras são heurísticas e mapeiam padrões comuns às categorias do **OWASP Top 10:2025**. O VibeCheck é uma ferramenta de apoio e conscientização, **não** substitui uma auditoria completa nem um checklist de conformidade.

## ✨ Funcionalidades

- 🔍 **Análise de código** por upload de arquivo ou colagem de trecho
- 🧠 **Contexto do achado:** linha, severidade, evidência, impacto e recomendação
- 📚 **Mapeamento OWASP Top 10:2025** e referências CWE
- 📄 **Relatório em PDF** com prioridades e localização dos problemas
- 🕘 **Histórico de análises** persistido no banco (modo com API)
- 🔐 **Cadastro e login** com autenticação no backend
- 💻 **Modo local no navegador:** sem `VITE_API_URL`, a análise roda no próprio browser, sem enviar código a servidor
- 🤖 **Revisão automática de Pull Requests** via GitHub Actions, com comentários inline nas linhas novas

## 🧱 Stack e arquitetura

| Camada | Tecnologia |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | FastAPI (Python), autenticação e motor de análise |
| Banco de dados | MySQL 8.4 (SQLite opcional para testes rápidos) |
| Infraestrutura | Docker Compose |
| CI/CD | GitHub Actions (revisão de PRs) |
| Testes | `pytest` (backend), `npm test` (frontend) |

```
┌──────────────┐   HTTP /api    ┌───────────────┐      ┌──────────┐
│   Frontend   │ ─────────────► │    Backend    │ ───► │  MySQL   │
│ React + Vite │ ◄───────────── │    FastAPI    │ ◄─── │   8.4    │
└──────────────┘                └───────────────┘      └──────────┘
   :5173                           :8000 (/docs)          :3306
```

### Estrutura de pastas

```
.
├── frontend/             # React + TypeScript + Vite
├── backend/              # API FastAPI, autenticação e scanner
├── database/
│   └── schema.sql        # criação do banco e usuário MySQL
├── .github/workflows/    # revisão automática de Pull Requests
├── .vscode/              # configurações do workspace
├── docker-compose.yml    # MySQL + backend + frontend
└── .env.example          # exemplo de configuração (sem credenciais reais)
```

## 🚀 Como rodar

### Pré-requisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) **ou** Python 3.10+, Node.js 18+ e MySQL 8.4
- Git

### Opção 1 — Tudo com Docker (recomendado)

```powershell
# 1. Clone o repositório
git clone https://github.com/joaovieira01/VibeCheck_Lobios.git
cd VibeCheck_Lobios

# 2. Configure as variáveis (altere TODAS as senhas)
Copy-Item .env.example .env

# 3. Suba os serviços
docker compose up --build
```

| Serviço | URL |
|---|---|
| Frontend | http://localhost:5173 |
| API | http://localhost:8000 |
| Documentação da API | http://localhost:8000/docs |
| MySQL | `localhost:3306` |

Para subir **apenas o banco** durante o desenvolvimento:

```powershell
docker compose up -d mysql
```

### Opção 2 — Execução manual

#### 1) Banco de dados

Execute `database/schema.sql` no MySQL (Workbench ou terminal) e **troque `CHANGE_THIS_PASSWORD`** por uma senha forte. Ou use apenas o MySQL do Docker (`docker compose up -d mysql`).

#### 2) Backend

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Copie `.env.example` para `.env` na raiz e configure `VIBECHECK_DB_PASSWORD`. Em seguida, inicie a API:

```powershell
uvicorn app.main:create_app --factory --reload
```

> Para testar rapidamente com SQLite, use `VIBECHECK_DB_ENGINE=sqlite` e `VIBECHECK_DB_PATH=data/vibecheck.db`.

#### 3) Frontend

```powershell
cd frontend
npm install
Copy-Item .env.local.example .env.local
npm run dev
```

Abra http://localhost:5173.

### ⚙️ Variáveis de ambiente

| Variável | Descrição | Exemplo |
|---|---|---|
| `VIBECHECK_DB_ENGINE` | Banco usado pelo backend | `mysql` ou `sqlite` |
| `VIBECHECK_DB_HOST` / `PORT` | Endereço do MySQL | `127.0.0.1` / `3306` |
| `VIBECHECK_DB_NAME` | Nome do banco | `vibecheck` |
| `VIBECHECK_DB_USER` | Usuário exclusivo da aplicação | `vibecheck_user` |
| `VIBECHECK_DB_PASSWORD` | Senha do banco | *defina uma senha forte* |
| `VIBECHECK_CORS_ORIGINS` | Origens permitidas no CORS | `http://localhost:5173` |
| `VIBECHECK_FRONTEND_URL` | URL do frontend | `http://localhost:5173` |
| `VIBECHECK_RATE_LIMIT` | Limite de requisições | `true` |
| `VIBECHECK_SEED_DEMO_USER` | Cria usuário de demonstração | `false` |
| `VITE_API_URL` | URL da API usada pelo frontend | `http://localhost:8000` |

> Sem `VITE_API_URL`, o frontend funciona em **modo local**: cadastro, análise e histórico ficam no navegador.

## 🔌 Integração frontend ↔ API

Com `VITE_API_URL` definido em `frontend/.env.local`:

- Cadastro e login usam `/api/auth/register` e `/api/auth/login`
- Análises e histórico são enviados para `/api/analyses` e persistidos no banco

A recuperação de senha já possui endpoints no backend (exige SMTP configurado), mas a tela correspondente no frontend ainda será integrada.

## 🧪 Testes

```powershell
# Backend
cd backend
pytest

# Frontend
cd frontend
npm test
npm run build
```

## 🤖 Revisão automática de Pull Requests

O workflow `.github/workflows/aura-scanner.yml` executa o scanner nas alterações de Pull Requests e publica **comentários inline** nas linhas novas que tiverem achados.

- Lê os arquivos pela API do GitHub, com limite de tamanho e tempo
- **Não executa** o código do Pull Request
- Token com permissões mínimas: `contents: read` e `pull-requests: write`
- Não exige cadastro manual de segredos
- Os comentários explicam como corrigir, mas **não alteram o código** automaticamente

## 🔒 Segurança

- Nunca publique arquivos `.env`
- Troque **todas** as senhas de exemplo
- Não habilite `VIBECHECK_SEED_DEMO_USER` em ambientes expostos
- Use uma conta MySQL exclusiva da aplicação, sem privilégios de administrador
- O `docker-compose.yml` expõe o MySQL em `3306` para facilitar o desenvolvimento; em outros ambientes, restrinja o acesso (ex.: `127.0.0.1:3306:3306`)
- O compose atual usa `--reload` e instala dependências ao iniciar: **é uma configuração de desenvolvimento**, não de produção

## 🗺️ Limitações e próximos passos

- [x] Análise heurística com mapeamento OWASP Top 10:2025
- [x] Relatório em PDF
- [x] Autenticação e histórico persistido
- [x] Revisão automática de PRs no GitHub
- [ ] Tela de recuperação de senha no frontend
- [ ] Integração com GitLab e Bitbucket
- [ ] Mais regras de detecção e maior cobertura por categoria
- [ ] Configuração de deploy de produção para backend e banco

> Categorias que dependem de decisões de design (como **A06 — Design inseguro**) exigem revisão manual e não são totalmente cobertas por heurísticas.

## 🤝 Contribuindo

1. Faça um fork ou crie uma branch: `git checkout -b feat/minha-melhoria`
2. Faça commits claros: `git commit -m "feat: descreve a mudança"`
3. Envie a branch: `git push origin feat/minha-melhoria`
4. Abra um Pull Request descrevendo o que mudou e como testar

## 👤 Autor

Feito por **João Vieira**: [@joaovieira01](https://github.com/joaovieira01)

---

<div align="center">

**VibeCheck** · Segurança de código com clareza em cada etapa.

</div>
