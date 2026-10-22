# VibeCheck — workspace completo

Projeto organizado para abrir **frontend, backend e banco de dados** na mesma pasta do Visual Studio Code.

## Estrutura

- `frontend/`: React + TypeScript + Vite
- `backend/`: API FastAPI, autenticação e scanner
- `database/schema.sql`: criação do banco e usuário MySQL
- `docker-compose.yml`: opção para subir MySQL 8.4 em Docker
- `.env.example`: exemplo de configuração local (não contém credenciais válidas)

## 1. Preparar o MySQL

Escolha **uma** opção:

### Opção A — MySQL já instalado no Windows
1. Abra o MySQL Workbench ou o terminal `mysql` como administrador.
2. Execute o conteúdo de `database/schema.sql`.
3. Substitua `CHANGE_THIS_PASSWORD` por uma senha forte no SQL e nos arquivos `.env`.

### Opção B — Docker
Instale o Docker Desktop, copie `.env.example` para `.env`, altere as senhas e execute `docker compose up -d mysql`.
O banco e o usuário são criados pelo container. Não use as senhas de exemplo fora de um ambiente local.

## 2. Configurar o backend
No terminal do VS Code:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

Copie o arquivo raiz `.env.example` para `.env` e configure `VIBECHECK_DB_PASSWORD`. O backend carrega esse arquivo automaticamente com `python-dotenv`; mantenha-o fora do Git.

Para rodar temporariamente com SQLite, use `VIBECHECK_DB_ENGINE=sqlite` e `VIBECHECK_DB_PATH=data/vibecheck.db`.

Configure as variáveis no terminal antes de iniciar, por exemplo:

```powershell
$env:VIBECHECK_DB_ENGINE="mysql"
$env:VIBECHECK_DB_HOST="127.0.0.1"
$env:VIBECHECK_DB_PORT="3306"
$env:VIBECHECK_DB_NAME="vibecheck"
$env:VIBECHECK_DB_USER="vibecheck_user"
$env:VIBECHECK_DB_PASSWORD="SUA_SENHA"
$env:VIBECHECK_CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
$env:VIBECHECK_FRONTEND_URL="http://localhost:5173"
uvicorn app.main:create_app --factory --reload
```

A API fica em `http://localhost:8000`; documentação em `http://localhost:8000/docs`.

## 3. Subir tudo em um único ambiente local
Para iniciar o banco, a API e o frontend juntos usando Docker:

```powershell
docker compose up --build
```

Isso levanta automaticamente:
- MySQL em `localhost:3306`
- backend em `http://localhost:8000`
- frontend em `http://localhost:5173`

Se quiser rodar somente o banco em desenvolvimento:

```powershell
docker compose up -d mysql
```

## 4. Configurar o frontend
Abra um segundo terminal:

```powershell
cd frontend
npm install
Copy-Item .env.local.example .env.local
npm run dev
```

O frontend abre em `http://localhost:5173`.

**Integração:** quando `VITE_API_URL` está definido em `frontend/.env.local`, os formulários de cadastro/login usam `/api/auth/register` e `/api/auth/login`, e as análises/histórico são enviados para `/api/analyses`, que persiste os dados no banco configurado no backend. Sem `VITE_API_URL`, o frontend usa o modo local no navegador. A recuperação de senha pela tela ainda precisa de uma integração de interface dedicada; a API já oferece os endpoints e exige SMTP para enviar e-mails.

## 4. Testes
Backend:

```powershell
cd backend
pytest
```

Frontend:

```powershell
cd frontend
npm test
npm run build
```

## Segurança
- Não publique arquivos `.env`.
- Não habilite `VIBECHECK_SEED_DEMO_USER` em ambientes expostos.
- Troque todas as senhas de exemplo.
- Use uma conta MySQL exclusiva da aplicação, sem privilégios de administrador.
