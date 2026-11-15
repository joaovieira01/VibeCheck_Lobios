# Integrações de CI/CD

O VibeCheck pode rodar no pipeline e interrompê-lo quando encontrar achados na
severidade configurada. GitLab CI e Bitbucket Pipelines clonam este repositório
para obter o CLI e analisam o checkout do projeto. O relatório SARIF fica
disponível como artefato do job. O scanner usa regras locais: não baixa bases de
vulnerabilidades nem envia o código para um serviço externo.

## GitHub Actions

No repositório VibeCheck, o workflow existente
`.github/workflows/vibecheck-pr-review.yml` analisa Pull Requests e publica
comentários nas linhas novas. O exemplo e os eventos estão em
[`integrations/github/README.md`](../integrations/github/README.md).

Esse workflow usa `backend/scripts/github_pr_review.py` e não é uma Action
reutilizável para instalar em outro repositório. Para um pipeline externo, use o
CLI conforme os exemplos GitLab e Bitbucket, ou execute-o diretamente:

```sh
python backend/scripts/scan_repo.py . --format sarif --fail-on Alta > vibecheck.sarif
```

O CLI retorna código `1` quando encontra um achado na severidade escolhida ou
mais grave. Assim, o job falha e o pipeline pode bloquear o merge. Sem
`--fail-on`, um achado não altera o código de saída.

## GitLab CI

Copie [`integrations/gitlab/.gitlab-ci.yml`](../integrations/gitlab/.gitlab-ci.yml)
para `.gitlab-ci.yml` na raiz do projeto. O job roda em Merge Requests, usa
Python 3.12 e publica `vibecheck.sarif` como artefato por uma semana, inclusive
quando a análise falha.

As variáveis podem ser configuradas em **Settings > CI/CD > Variables**:

| Variável | Padrão | Uso |
|---|---|---|
| `VIBECHECK_REPO_URL` | `https://github.com/joaovieira01/VibeCheck_Lobios.git` | URL do repositório que contém o CLI. |
| `VIBECHECK_FAIL_ON` | `Alta` | Severidade mínima que falha o job: `Crítica`, `Alta`, `Média` ou `Baixa`. |

Se o repositório VibeCheck for privado, forneça acesso de leitura ao job por
meio das variáveis protegidas do GitLab. Não grave tokens na URL versionada.

## Bitbucket Pipelines

Copie [`integrations/bitbucket/bitbucket-pipelines.yml`](../integrations/bitbucket/bitbucket-pipelines.yml)
para `bitbucket-pipelines.yml` na raiz do projeto e habilite o Bitbucket Pipelines.
O step executa em Pull Requests e publica `vibecheck.sarif` como artefato.

Cadastre `VIBECHECK_REPO_URL` e, opcionalmente, `VIBECHECK_FAIL_ON` em
**Repository settings > Pipelines > Repository variables**. Os padrões são a URL
pública do projeto e `Alta`. Para repositórios privados, configure credenciais
de leitura como variáveis seguras; não as inclua no YAML.

## Arquivos alterados

Os exemplos acima analisam o checkout inteiro. Para executar localmente somente
os arquivos modificados em relação a uma referência Git disponível:

```sh
python backend/scripts/scan_repo.py . --changed-since origin/main --format sarif --fail-on Alta > vibecheck.sarif
```

`--changed-since` usa `git diff --name-only REF` e exige um diretório dentro de
um repositório Git, além de uma referência conhecida localmente. Arquivos
apagados não são analisados. Sem essa opção, o CLI mantém a varredura completa.

## Disponibilidade atual e roadmap

| Plataforma e modo | Suportado hoje (CI/CLI) | Planejado (webhook/app nativo com comentário inline) |
|---|---|---|
| GitHub Actions | Sim. Workflow do projeto com comentários automáticos; CLI também pode gerar SARIF. | App reutilizável para outros repositórios e comentários gerenciados por app. |
| GitLab CI | Sim. Pipeline de exemplo, falha por severidade e artefato SARIF. | Webhook ou app nativo com comentários inline no Merge Request. |
| Bitbucket Pipelines | Sim. Pipeline de exemplo, falha por severidade e artefato SARIF. | Webhook ou app nativo com comentários inline no Pull Request. |

Nos exemplos de GitLab e Bitbucket, o relatório é um artefato do pipeline; eles
não publicam comentários inline nem integram os achados a uma tela nativa de
segurança dessas plataformas.
