# Progresso

## Etapa 0 — Medição (histórico)

**Estado:** linha de base implementada e executada; comportamento do scanner sem mudanças.

- `rules.json`: 19 regras declaradas. `scanner.ts`: 19 regras estáticas mais a regra sintética `unlocked-dependency` (20 executadas); `scanner.py` também executava 20. Os 19 IDs estáticos coincidiam nos dois lados.
- Recall total: **8/28 (28,6%)**. Os 7 itens `control` atingiram **7/7 (100%)**.
- Recall por categoria OWASP: A01 **0/8**, A02 **0/1**, A04 **0/3**, A05 **0/5**, A07 **1/2**, A10 **0/1**. Itens `control` são contabilizados separadamente.
- Achados sem correspondência exata de regra/linha no gabarito: **2** — `weak-password-hash` na linha 75 (não correspondia ao problema real) e `server-all-interfaces` na linha 187.
- Amostra segura: **0 achados**. Tempo: vulnerável **0,004062 s**, segura **0,004418 s**, total **0,008480 s**.
- Paridade: nenhuma diferença de regra/linha/evidência nas duas amostras; diferenças de metadados na amostra vulnerável em `hardcoded-secret`, `pickle`, `dynamic-eval`, `command-injection`, `sql-injection`, `unsafe-yaml`, `weak-password-hash`, `debug-mode` e `server-all-interfaces`. Na amostra segura, nenhuma diferença.
- Decisão da etapa: manter comportamento inalterado; registrar as divergências para serem resolvidas na etapa 1.
- Comandos executados: métricas Python; testes pytest focados (**11 testes e 19 subtestes**); `py_compile`; `npm ci`; Vitest (**3 arquivos, 9 testes**). Todos passaram.

## Etapa 1 — Qualidade das regras

**Estado:** concluída; sem commit ou push.

- Frontend e backend leem os metadados e expressões de `backend/app/rules.json`. O teste de paridade estrita compara achados completos (ID, metadados, linhas e evidências) entre TypeScript e Python.
- `rules.json` contém **41 regras**: 40 para código e uma para manifestos. Existem regras mapeadas em todas as categorias OWASP Top 10:2025, A01–A10; isso não significa cobertura completa de cada categoria.
- As 21 regras para as lacunas têm casos positivos e negativos no corpus golden. A métrica passou a exigir o `expectedRuleId`; `server-all-interfaces` é verificado separadamente como achado esperado na linha 187.
- `weak-password-hash` foi restringida a ocorrências de MD5/SHA-1 com contexto de `password`, `passwd`, `senha` ou `pwd`. Antes, sinalizava qualquer chamada a esses algoritmos; agora o hash do token na linha 75 é atribuído a `weak-token-hash`.
- Confiança está definida em todas as regras (`alta`, `média`, `baixa`). As regras contextuais `mass-assignment`, `missing-authentication`, `csrf-get-mutable`, `toctou` e `user-enumeration` usam confiança baixa.
- `/api/health`, `/api/rules` e os esquemas da API expõem a contagem/metadados atualizados.

### Métricas após a etapa 1

- Recall pela regra correta: **28/28 (100%)**.
- Detectado por regra errada na linha: **0**; não detectado: **0**.
- Controles: **7/7**, pela regra esperada.
- Achado adicional esperado `server-all-interfaces`: **1/1**.
- Achados sem correspondência no gabarito: **0**; amostra segura: **0 achados**.
- Recall pelas categorias representadas nos 28 itens: A01 **9/9**, A04 **3/3**, A05 **5/5**, A07 **2/2**, A10 **1/1**. O achado adicional A02 foi detectado à parte (**1/1**).
- Tempo dessa execução: vulnerável **0,043683 s**, segura **0,036776 s**, total **0,080459 s**.

### Verificações executadas

- `node --experimental-strip-types scripts\generate_golden.mjs ..\frontend` (em `backend`): **40 casos gravados**.
- `python -m pytest` (em `backend`): **56 passaram**, um aviso Starlette/httpx sobre descontinuação.
- `npm run build` (em `frontend`): **passou**, `tsc -b` e Vite.
- `npm test` (em `frontend`): **3 arquivos, 11 testes passaram**.
- `python scripts\metrics.py` (em `backend`): **passou**, relatório textual e JSON.
- Testes incluem pares positivos/negativos por regra e uma linha de 1.000 caracteres para exercitar regex.

### Limitações e pendências

- Nenhum item da amostra ficou sem detecção nesta execução. As regras continuam heurísticas por linha e dependem de formas de código próximas às amostras; não substituem análise de fluxo, autorização contextual ou SAST completo.
- O `npm ci` não foi necessário nesta etapa: as dependências já estavam presentes e nenhum manifesto/lockfile foi alterado.
