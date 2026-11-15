# Revisão técnica para a banca

**Data da verificação:** 15/11/2026  
**Escopo:** conferir documentação e arquivos de demonstração contra o código,
executar testes/build/métricas e procurar segredos e artefatos versionados.

## Inconsistências corrigidas

- [backend/README.md](../backend/README.md) dizia que havia 19 regras e 19 casos
  golden. O código contém **41 regras** (40 para código e uma de manifesto) e o
  corpus tem **64 casos**.
- O README do backend não listava as três rotas de repositório. Agora registra
  POST, lista e detalhe em `/api/repositories/analyses`, com autenticação,
  limite padrão de ZIP de 25 MB e rate limit de 5 análises por usuário/hora.
- A documentação de configuração não listava `VIBECHECK_MAX_REPO_ZIP_BYTES` e
  tinha valores incompletos para CORS, scrypt e rate limit. Os READMEs e
  exemplos de ambiente agora refletem defaults e controles atuais.
- O roadmap raiz ainda marcava a sugestão de correção como não implementada;
  agora está marcada como disponível, com escopo limitado e sem aplicação
  automática.
- A documentação agora separa a checagem online do backend do modo local do
  frontend e descreve quais metadados de dependências saem para OSV/PyPI/npm.
- GitLab e Bitbucket são descritos como integrações CI/CLI disponíveis; apps
  nativos e comentários inline continuam planejados. A documentação informa
  que os YAMLs não foram executados nas plataformas reais.
- O `docker-compose.yml` não encaminhava os limites de repositório nem
  `VIBECHECK_ONLINE_DEPS` configurados no `.env`. Corrigi o repasse das
  variáveis de análise para o serviço backend. Isso não transforma o Compose
  atual em configuração de produção; ele ainda usa `--reload`.

## Testes e medições reproduzidos

Saída do backend:

```text
collected 201 items
...
======================= 201 passed, 1 warning in 42.72s =======================
```

O aviso é de depreciação Starlette/httpx; não houve skips.

Saída do frontend:

```text
Test Files  7 passed (7)
Tests  43 passed (43)
✓ built in 5.12s
```

Medições atuais:

| Comando | Resultado |
|---|---|
| `python scripts/metrics.py` | Recall interno 28/28, 0 por regra errada, 0 não detectados, achado extra esperado 1/1, amostra segura 0; 0,069514 s. |
| `python scripts/benchmark.py` | 27/28 (96,4%) recall, 28/30 (93,3%) precisão, 2/30 (6,7%) sem rótulo, 0,063674 s. |
| `python scripts/bench_repo.py` | 500/500 arquivos sintéticos, 0 achados, 0,252 s. |

O benchmark de 40 arquivos foi escrito pela equipe e medido depois dos ajustes.
Não é uma avaliação externa, cega ou representativa de produção. Um caso de
path traversal tem rótulo uma linha abaixo do código; há também SSRF adicional
num arquivo cujo rótulo principal é TLS.

## Varredura de segredos e arquivos

- Não encontrei tokens com os formatos pesquisados de Stripe, AWS, GitHub,
  Google ou Slack em código de produção. As ocorrências estão em testes,
  corpus golden e relatórios de scanner com **valores deliberadamente
  fictícios**. Não foram copiados valores de credenciais para este relatório.
- Há placeholders de senha nos `.env.example` e no schema SQL. A credencial
  `demo@vibecheck.dev` / `vibecheck2026` é pública e documentada como demo; o
  seed é desligado por padrão e bloqueado em produção.
- O `.env` local existe, mas é ignorado pelo Git; não foi lido nem incluído.
  Só `.env.example` e exemplos semelhantes estão versionados.
- Não foram encontrados `.db`, SQLite, `.venv`, `node_modules`, `dist`,
  `build`, SARIF, ZIP ou capturas de tela versionados antes desta revisão.
  `backend/tests/benchmark/report.json` é o relatório gerado e versionado pelo
  benchmark; foi atualizado pela execução solicitada. O ZIP em `demo/` é um
  fixture intencional e é a única exceção nova para arquivos `.zip`.
- As URLs locais encontradas são exemplos de `localhost`/loopback em
  configurações, documentação e testes locais. Dois endereços loopback
  adicionais pertencem a testes do cliente HTTP. Não encontrei URL com
  credenciais, IP privado de serviço ou domínio `.local` versionado.

O [`.gitignore`](../.gitignore) já protegia `.env`, ambientes virtuais, bancos e
artefatos do frontend. Acrescentei exclusão para `*.sarif`, `*.zip` e pastas
locais `screenshots/` e `capturas/`, com exceção explícita para
`demo/vibecheck-demo.zip`.

## Pendências reais

- Não existem `docker-compose.prod.yml`, `frontend/Dockerfile.prod` nem
  configuração Nginx.
- A tela de recuperação de senha e a tela de resultados da camada de IA não
  existem; os endpoints de recuperação e a camada de IA no backend existem.
- O workflow GitHub comenta PRs, mas não bloqueia merge sem configuração
  externa de branch protection.
- GitLab/Bitbucket têm exemplos de CI/CLI, não app/webhook/comentários inline;
  não houve execução em runners reais.
- Não foram medidos repositórios reais grandes nem testados serviços OSV/PyPI/
  npm ou provedores de IA ao vivo nesta revisão.
- O SCA online é opcional, backend-only e depende de serviços públicos; seus
  testes usam cliente falso e não fazem rede.

Veja [Limitações](LIMITACOES.md), [Roteiro da demo](DEMO.md),
[Perguntas da banca](PERGUNTAS_DA_BANCA.md) e [métricas](BENCHMARK.md) para
detalhes e falas sugeridas.

