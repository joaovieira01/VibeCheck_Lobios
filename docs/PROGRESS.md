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

## Etapa 1.5 — Generalização e falsos positivos

**Estado:** concluída; sem commit. O `frontend/package-lock.json` permaneceu intacto.

### (a) Métricas nas amostras existentes

- Amostra vulnerável: **28/28 (100%)** pela regra esperada; **0** regras erradas e **0** não detectados.
- Achado adicional esperado: **1/1** (`server-all-interfaces`); **0** achados sem correspondência.
- Amostra segura: **0 achados**.
- Recall nas categorias representadas: A01 **9/9**, A04 **3/3**, A05 **5/5**, A07 **2/2**, A10 **1/1**.
- Tempo nesta execução: vulnerável **0,037474 s**, segura **0,045224 s**, total **0,082699 s**. São medidas locais, não uma garantia de desempenho geral.
- A expectativa de autenticação para `admin-sem-autenticacao` foi movida do corpo da operação para a declaração do handler, conforme o novo contrato de localização.

### (b) Autovarredura de produção

Foram examinados **23 arquivos** em `backend/app`, `backend/scripts` e `frontend/src`, excluindo testes e os exemplos vulneráveis demonstrativos de `App.tsx` (incluindo o trecho ilustrativo de SQL no hero). Resultado: **2 achados**, ambos legítimos como texto de implementação do scanner, não como consultas SQL:

| Arquivo/linha | Achado | Decisão |
|---|---|---|
| `frontend/src/services/scanner.ts:242` | `sql-injection` na regex que reconhece decoradores de rotas destrutivas | **Legítimo**: palavras HTTP dentro da regex do scanner, sem construção ou execução de SQL |
| `frontend/src/services/scanner.ts:244` | `sql-injection` na regex de métodos HTTP de rota | **Legítimo**: mesma causa; não é código de consulta |

O caso previamente observado em `backend/app/main.py:296` deixou de aparecer: a rota é avaliada pela assinatura do handler e o alias `User = Annotated[..., Depends(...)]` é reconhecido como autenticação. Não foram encontrados outros achados em produção.

### (c) Regras alteradas — antes/depois

| Regra/classe | Antes | Depois |
|---|---|---|
| Comentários e docstrings | Padrões em comentários e strings Python de bloco podiam ser sinalizados | Comentários Python/JS e strings Python de bloco são mascarados antes do matching; as quebras de linha e os números originais são preservados |
| `missing-authentication` | Operações genéricas podiam marcar o decorador e a autenticação próxima tinha pouco contexto | Rotas Flask/FastAPI/Django e Express são avaliadas no handler; reconhece dependências/decoradores/middleware, parâmetros autenticados e aliases `Annotated` com `Depends`; operações isoladas continuam cobertas |
| `zip-slip` | Qualquer `extractall`/`extractTo` podia disparar | `filter=` e evidências próximas de canonicalização/validação de caminho são controles seguros |
| SSRF e redirecionamento | Poucas chamadas e fontes diretas (`requests`/`httpx`, `request.args`, `req.query/body`) | Chamadas qualificadas de `urllib`, `aiohttp`/`session`, `axios`, `got`, `fetch`; fontes `GET`, `POST`, `args`, `form`, `json`, `query`, `params`, `body` e `payload`; redirect ganhou controles de destino seguro |
| Hash e comparação de segredos | Hash de token reconhecido em formatos estreitos; comparação focada em nomes de token | Hashes MD5/SHA-1 em variáveis de token, incluindo `createHash`; igualdade direta ampliada para nomes de segredo, assinatura e digest, mantendo `compare_digest`/`timingSafeEqual` como controles |
| Mass assignment, template, XPath | Poucas formas diretas de update e concatenação | `update(**dados)`, `findByIdAndUpdate`, entrada em template e XPath por concatenação, `%`, `.format`, f-string e template literal |
| AES, logs, paginação, upload e enumeração | Padrões limitados à amostra | `modes.ECB` e cifras ECB Node; entrada de usuário em log; mais fontes de paginação; nomes `filename`/`originalname`, incluindo callback Multer; mensagens e respostas 404 que revelam existência |
| Frontend | `scanner.ts` importava `../../../backend/app/rules.json` | Importa `src/data/rules.generated.json`, gerado de `rules.json` por `npm run sync:rules`; teste backend verifica igualdade byte a byte |

### (d) Novos testes

- O corpus passou de **40 para 64 casos**; são **45 casos com `ruleCheck`**.
- Foram adicionadas **12 classes generalizadas**, cada uma com casos Python e JS/TS, pelo menos dois positivos com formas distintas e um controle seguro: SSRF, hash de token, comparação de segredo, mass assignment, template injection, AES-ECB, log injection, paginação, upload, XPath, enumeração e autenticação.
- Os testes cobrem também comentários/docstrings com linhas preservadas, `extractall(filter=...)`, autenticação FastAPI/Express/Django e cópia gerada das regras.

### (e) Instalação, testes e portabilidade

- `npm ci` em `frontend`: **112 pacotes adicionados; 113 auditados; 0 vulnerabilidades**. O npm avisou que os scripts `postinstall` de `core-js` e `esbuild` ainda não estão aprovados por `allowScripts`; o build executado passou. O lockfile não mudou.
- `python -m pytest` em `backend`: **63 passaram**, com um aviso de depreciação Starlette/httpx.
- `npm test` em `frontend`: **14 testes passaram** em 3 arquivos.
- `npm run build` em `frontend`: **passou** (`tsc -b` e Vite). O scanner não depende mais de arquivos fora de `frontend/`, então esse build consome as regras geradas também em contexto Docker/Vercel isolado.
- `git diff --check`: passou.
- Não foi possível executar `docker compose up`: o executável Docker/Compose não está instalado/disponível neste ambiente. A configuração, portanto, não foi validada com containers em execução.

### (f) Limites do que foi generalizado

- Não foi fornecido o corpus externo das 25 falhas; portanto, **não afirmo recall medido nele**. Os 100% são apenas das amostras existentes, e os novos positivos/negativos do corpus golden.
- As regras continuam heurísticas por linha/função, não fazem análise completa de fluxo de dados. Não generalizam automaticamente variáveis intermediárias, wrappers próprios, aliases arbitrários de bibliotecas, middleware customizado não nomeado como autenticação, nem construções multilinha complexas.
- A proteção de upload e extração reconhece APIs/validações comuns; callbacks próprios e sanitizadores customizados precisam ser adicionados quando usados. `filter=` é aceito como sinal seguro sem avaliar a implementação do filtro.
- Os dois resultados da autovarredura em `scanner.ts` ficam documentados como legítimos porque são os próprios padrões textuais das regexes de rota, não uso de SQL.
