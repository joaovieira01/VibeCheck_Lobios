# Limitações conhecidas e itens não implementados

Esta lista descreve o estado do MVP em 15/11/2026. Não é uma lista de promessas
nem uma certificação de segurança.

## Análise estática

- As regras são heurísticas por linha/contexto. Não há AST completo, análise de
  fluxo de dados entre funções/arquivos, execução do programa ou prova de
  explorabilidade.
- Wrappers, aliases de bibliotecas, sanitizadores próprios, código gerado e
  construções multilinha podem escapar ou gerar falsos positivos.
- Linhas acima de 1.000 caracteres são truncadas antes das regras; arquivos
  acima de 1 MB são ignorados na análise de repositório. Só extensões
  explicitamente suportadas são analisadas.
- O benchmark de regras usa 40 arquivos, 29 rótulos e exemplos da equipe. Na
  execução de 15/11/2026 marcou 29/29 (100,0%) recall, 30/30 (100,0%)
  precisão e 0/30 (0,0%) achados sem rótulo, em 0,058725 s. Os rótulos foram
  corrigidos depois de observar execuções anteriores; portanto, não é uma
  avaliação independente ou cega, nem uma taxa medida em produção.

## Dependências (SCA)

- A checagem online é opcional, exclusiva do backend e depende de OSV, PyPI e
  npm estarem acessíveis. O frontend em modo local não faz essas chamadas.
- A análise cobre `requirements.txt` e os grupos dependencies,
  devDependencies e optionalDependencies de `package.json`; não resolve todos
  os lockfiles, dependências transitivas, registries privados ou dependências
  instaladas.
- OSV é consultado somente para versões fixadas. Cada manifesto limita a
  consulta aos primeiros 50 pacotes. A cobertura e a atualização dos dados
  dependem das fontes externas.
- Só um 404 confirmado no registry marca pacote inexistente. Timeout, erro de
  rede, resposta inválida e 5xx significam “verificação online indisponível”,
  não pacote seguro ou inexistente.
- A consulta envia nomes a PyPI/npm e ecossistema, nome e versão fixada ao OSV.
  Nenhum trecho de código é enviado pela camada SCA. Isso é diferente da IA,
  que pode transmitir trechos quando habilitada.

## Repositórios e API

- ZIP enviado à API tem limite padrão de 25 MB; extração tem limites próprios
  (50 MB descompactados e 2.000 arquivos). A análise pode ser parcial ao atingir
  o limite de tempo.
- O endpoint de repositório exige login e permite 5 análises por usuário por
  hora. O rate limit é em memória por processo, não um limite distribuído entre
  várias instâncias.
- O benchmark de repositório analisou 500/500 arquivos sintéticos, com 0
  achados, em 0,296 s na execução de 15/11/2026. O tempo depende da máquina e
  não representa monorepos, arquivos grandes, armazenamento compartilhado ou
  concorrência real.
- Histórico guarda achados e evidências; uma linha contendo segredo detectado
  pode ser persistida. Proteja o banco e limite acesso ao histórico.
- SQLite é adequado para uma instância local/teste; produção multi-instância
  requer banco e rate limit compartilhados.

## Produto, deploy e integrações

- **Não existe** `docker-compose.prod.yml`, `frontend/Dockerfile.prod` nem
  configuração Nginx neste repositório. O `docker-compose.yml` atual é de
  desenvolvimento, usa `--reload` e não foi validado em ambiente de produção.
- Os endpoints de recuperação de senha existem, mas a tela de recuperação no
  frontend não foi implementada.
- A camada de IA existe no backend/CLI; a exibição dedicada dos resultados de
  IA no frontend não foi implementada.
- O workflow GitHub comenta achados em linhas novas, mas não bloqueia merge por
  si só. Branch protection é configuração externa.
- GitLab CI e Bitbucket Pipelines têm exemplos via CLI/artefato, mas não há
  webhook/app nativo nem comentário inline nessas plataformas. Os YAMLs não
  foram executados em serviços reais.
- Não houve validação em repositórios reais grandes, nem teste operacional de
  runners GitLab/Bitbucket, provedores de IA, OSV ou registries nesta revisão.

## Segurança operacional

- `VIBECHECK_SEED_DEMO_USER=true` cria uma conta com credencial pública de
  demonstração. O padrão é desligado e produção rejeita o seed; nunca habilite
  essa conta em ambiente exposto.
- Scrypt usa aproximadamente 128 MiB por operação. O semáforo é por processo;
  múltiplos workers multiplicam o consumo máximo possível.
- O rate limit e sessões não substituem monitoramento, MFA, verificação de
  e-mail ou gestão de incidentes. MFA e verificação de e-mail não existem.
- A camada de IA mascara alguns padrões, mas não garante remoção de segredos ou
  dados pessoais; confira a política de retenção do provedor antes de enviar
  código confidencial.

