# Roteiro de demonstração — 5 minutos

## Preparação

1. Rode `docker compose up --build` e aguarde API, frontend e MySQL ficarem prontos.
2. Crie uma conta de teste pela interface, ou entre com uma conta de demonstração
   previamente provisionada. A conta pública `demo@vibecheck.dev` /
   `vibecheck2026` **só existe se** `VIBECHECK_SEED_DEMO_USER=true`; o padrão é
   `false` e produção rejeita essa opção. Nunca trate essa credencial pública
   como conta privada nem habilite o seed no deploy.
3. Gere o ZIP de demonstração com `python demo/create_demo_zip.py`. Não instale
   `demo/requirements.txt`: ele inclui intencionalmente um nome de pacote falso.
4. Se for demonstrar SCA online, confirme a conexão e ative
   `VIBECHECK_ONLINE_DEPS=true`. Nomes de pacotes vão aos registries PyPI/npm e
   nome, ecossistema e versão fixada vão ao OSV. Nenhum código-fonte é enviado
   por essa checagem.

## Roteiro cronometrado

| Tempo | Ação | O que dizer |
|---|---|---|
| 0:00–0:40 | Abra a análise web e cole o conteúdo de `demo/vulnerable_python.py`. | “Este é um exemplo preparado de código no estilo de saída de IA. O scanner procura padrões de risco; não executa o código.” Não diga que o arquivo foi gerado ao vivo por IA. |
| 0:40–1:20 | Mostre `hardcoded-secret`, `debug-mode` e `sql-injection`, com as linhas e evidências. Copie uma correção sugerida. | “As sugestões são determinísticas e só aparecem quando o scanner reconhece uma transformação. Copiar não aplica nem valida a correção no projeto.” |
| 1:20–2:00 | Cole `demo/vulnerable_javascript.js` e mostre SQL injection e XSS. | “A mesma ideia funciona em mais de uma linguagem, mas as regras são heurísticas; não acompanham todo o fluxo de dados.” |
| 2:00–2:45 | Na aba **Repositório**, envie `demo/vibecheck-demo.zip` e abra um achado. | “O ZIP é extraído em área temporária e tem limites de tamanho e quantidade. A rota exige login; o limite é 5 análises por usuário por hora.” |
| 2:45–3:30 | Rode o CLI abaixo e mostre o SARIF e o código de saída. Mostre os YAMLs do GitLab/Bitbucket como exemplos de CI, não como execução ao vivo. | “`--fail-on Alta` retorna 1 para achados Alta ou Crítica. O bot GitHub comenta, mas não bloqueia merge sozinho. Os pipelines GitLab/Bitbucket não foram validados em serviços reais e não fazem comentários inline.” |
| 3:30–4:20 | Rode `demo/requirements.txt` com `--online-deps`. | “Versões fixadas são consultadas no OSV; PyPI/npm confirmam existência. Só um 404 confirmado indica pacote inexistente. Timeout ou 5xx significa que a verificação está indisponível, não que o pacote não existe.” |
| 4:20–5:00 | Mostre `docs/BENCHMARK.md` e `docs/LIMITACOES.md`. | “Na execução de 15/11/2026, o corpus interno marcou 29/29 (100,0%) de recall, 30/30 (100,0%) de precisão e 0/30 achados sem rótulo. Os rótulos foram corrigidos depois de observar resultados anteriores, então não é uma avaliação independente. O benchmark de repositório analisou 500/500 arquivos sintéticos, com 0 achados, em 0,296 s nesta máquina; não prova desempenho em repositórios reais.” |

## Comandos prontos

Execute na raiz do repositório, usando o ambiente Python do projeto:

```powershell
python demo\create_demo_zip.py
python backend\scripts\scan_repo.py demo\vibecheck-demo.zip --format sarif --fail-on Alta > vibecheck.sarif
$LASTEXITCODE
```

O código de saída esperado do segundo comando é `1`, pois o exemplo contém
achados Alta/Crítica. `vibecheck.sarif` é um arquivo de saída local e está
ignorado pelo Git.

Para a checagem online:

```powershell
$env:VIBECHECK_ONLINE_DEPS = "true"
python backend\scripts\scan_file.py demo\requirements.txt --online-deps
```

O manifesto inclui `requests==2.19.1` como exemplo de versão com aviso de
segurança conhecido e um nome inventado para exercitar 404. Os resultados
dependem do estado atual de OSV/PyPI. Não instalamos nem validamos esses pacotes
durante esta revisão.

## Plano B sem internet

- Demonstre os achados locais de Python/JavaScript, a correção sugerida e o ZIP;
  essas etapas não precisam de serviços externos de SCA.
- Não afirme que o pacote falso foi confirmado como inexistente nem que uma
  vulnerabilidade foi consultada ao vivo. Mostre `docs/BENCHMARK.md` e explique
  que os testes de dependências usam um cliente HTTP falso, sem rede.
- Se tentar a opção online, uma falha deve aparecer como
  **“Verificação online indisponível.”**. Não a apresente como resultado
  negativo nem como confirmação de pacote malicioso.
- Se a banca perguntar pela conta demo, informe que a senha é pública,
  `VIBECHECK_SEED_DEMO_USER` é desligado por padrão e produção bloqueia o seed.
  Prefira uma conta descartável criada para a demonstração.

