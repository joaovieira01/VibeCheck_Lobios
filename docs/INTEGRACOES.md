# Integrações de CI/CD

O VibeCheck pode rodar no pipeline e interrompê-lo quando encontrar achados na
severidade configurada. GitLab CI e Bitbucket Pipelines buscam uma versão configurada deste repositório
para obter o CLI e analisam o checkout do projeto. O scanner usa regras locais:
não baixa bases de vulnerabilidades nem envia o código para um serviço externo.

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
Python 3.12, define `GIT_DEPTH: "0"` e busca `CI_MERGE_REQUEST_DIFF_BASE_SHA`
antes de chamar `--changed-since`. O script captura e devolve explicitamente o
código de saída do CLI. O YAML configura `artifacts: when: always` para o
relatório `vibecheck.sarif`.

As variáveis podem ser configuradas em **Settings > CI/CD > Variables**:

| Variável | Padrão | Uso |
|---|---|---|
| `VIBECHECK_REPO_URL` | `https://github.com/joaovieira01/VibeCheck_Lobios.git` | URL do repositório que contém o CLI. |
| `VIBECHECK_REF` | `main` | Branch, tag ou commit usado para buscar o CLI. |
| `VIBECHECK_FAIL_ON` | `Alta` | Severidade mínima que falha o job: `Crítica`, `Alta`, `Média` ou `Baixa`. |

Se o repositório VibeCheck for privado, forneça acesso de leitura ao job por
meio das variáveis protegidas do GitLab. Não grave tokens na URL versionada.

## Bitbucket Pipelines

Copie [`integrations/bitbucket/bitbucket-pipelines.yml`](../integrations/bitbucket/bitbucket-pipelines.yml)
para `bitbucket-pipelines.yml` na raiz do projeto e habilite o Bitbucket Pipelines.
O pipeline configura clone completo e busca o commit de destino do Pull Request
antes de executar `--changed-since`.

O fluxo tem dois passos. O primeiro gera `vibecheck-report.json` sem
`--fail-on`, grava o status da análise e termina com sucesso para que seu
artefato compartilhado possa ser consumido pelo passo seguinte. O segundo
verifica esse status e executa `--check-report ... --fail-on ...`; é ele que
aplica a política e falha o pipeline quando o limite é atingido. Assim, a
captura do relatório não depende de um passo de análise terminar com falha.
`--check-report` aceita o JSON nativo do VibeCheck; não use um arquivo SARIF
nessa opção.

Cadastre `VIBECHECK_REPO_URL` e, opcionalmente, `VIBECHECK_FAIL_ON` em
**Repository settings > Pipelines > Repository variables**. Os padrões são a URL
pública do projeto e `Alta`. Configure também `VIBECHECK_REF`; o exemplo usa
`main`. Para repositórios privados, configure credenciais de leitura como
variáveis seguras; não as inclua no YAML.

## Fixar a versão do CLI

Os exemplos usam `VIBECHECK_REF` para buscar o VibeCheck. Para builds
reprodutíveis, configure essa variável com uma tag revisada ou um SHA de commit
completo, em vez de acompanhar `main`. Isso evita que uma alteração no scanner
mude silenciosamente o comportamento do pipeline. A mesma referência deve
existir e estar acessível no repositório indicado por `VIBECHECK_REPO_URL`.

## Análise local de arquivos alterados

Os pipelines de Pull Request analisam arquivos modificados em relação à base do
Pull Request. Para executar localmente somente os arquivos modificados em
relação a uma referência Git disponível:

```sh
python backend/scripts/scan_repo.py . --changed-since origin/main --format sarif --fail-on Alta > vibecheck.sarif
```

`--changed-since` usa `git diff --name-only REF` e exige um diretório dentro de
um repositório Git, além de uma referência disponível localmente. Arquivos
apagados não são analisados. O CLI rejeita referências iniciadas por hífen,
com espaços ou caracteres de controle. Se o Git não encontrar a referência,
busque o commit base (por exemplo, `git fetch origin <ref>` ou
`git fetch --unshallow`) e execute novamente; o CLI informa esse procedimento e
não troca silenciosamente para uma varredura completa.

## O que foi validado

O CLI foi exercitado por testes automatizados locais: varredura de dois
repositórios Git temporários, seleção de arquivos alterados, rejeição de refs
maliciosas, erro quando a referência não está disponível e aplicação da
política em relatórios JSON. Os testes não executam workflows remotos.

Os arquivos YAML de GitLab CI e Bitbucket Pipelines **não foram executados em
instâncias reais dessas plataformas**. Portanto, não afirmamos validação
operacional de seus runners, permissões, variáveis nem do upload/compartilhamento
dos artefatos. No Bitbucket, o desenho evita depender de artefatos de um passo
falho: a etapa que os produz termina com sucesso e o passo seguinte aplica a
política.

## Disponibilidade atual e roadmap

| Plataforma e modo | Suportado hoje (CI/CLI) | Planejado (webhook/app nativo com comentário inline) |
|---|---|---|
| GitHub Actions | Sim. Workflow do projeto com comentários automáticos; CLI também pode gerar SARIF. | App reutilizável para outros repositórios e comentários gerenciados por app. |
| GitLab CI | Sim. Pipeline de exemplo, falha por severidade e artefato SARIF. | Webhook ou app nativo com comentários inline no Merge Request. |
| Bitbucket Pipelines | Sim. Pipeline de exemplo, falha por severidade e artefato JSON. | Webhook ou app nativo com comentários inline no Pull Request. |

Nos exemplos de GitLab e Bitbucket, o relatório é um artefato do pipeline; eles
não publicam comentários inline nem integram os achados a uma tela nativa de
segurança dessas plataformas.
