# Progresso

## Etapa 0 — Medição

**Estado:** linha de base implementada e executada; scanner sem mudanças.

- `rules.json`: 19 regras declaradas. `scanner.ts`: 19 regras estáticas mais a regra sintética `unlocked-dependency` (20 executadas); `scanner.py` também executa 20. Os 19 IDs estáticos coincidem nos dois lados, e a regra sintética existe nos três.
- Adicionadas as amostras vulnerável e segura, o gabarito, `backend/scripts/metrics.py` e testes para recall de 100% nos itens `control` e zero achados na amostra segura.
- Recall total: **8/28 (28,6%)**.
- Recall por categoria OWASP: A01 **0/8 (0%)**; A02 **0/1 (0%)**; A04 **0/3 (0%)**; A05 **0/5 (0%)**; A07 **1/2 (50%)**; A10 **0/1 (0%)**. Os 7 itens `control` são verificados separadamente e atingiram **7/7 (100%)**.
- Achados sem correspondência exata de regra/linha no gabarito: **2** — `weak-password-hash` na linha 75 (nota do gabarito: achado não corresponde ao problema real) e `server-all-interfaces` na linha 187.
- Achados na amostra segura: **0**. Tempo medido na execução final: vulnerável **0,004062 s**, segura **0,004418 s**, total **0,008480 s**.
- Comparação de scanners: nenhuma diferença de regra/linha/evidência nas duas amostras; ambos executam 20 regras. Na amostra vulnerável há diferenças de metadados:
  - `hardcoded-secret`: title, severity, owaspName, description, recommendation, impact, prevention.
  - `pickle`: title, severity, description, recommendation, impact, prevention.
  - `dynamic-eval`: title, severity, owaspName, description, recommendation, impact, prevention.
  - `command-injection`: title, severity, owaspName, description, impact.
  - `sql-injection`: title, severity, owaspName, description, recommendation, impact, prevention.
  - `unsafe-yaml`: title, description, impact, prevention.
  - `weak-password-hash`: title, owaspName, description, recommendation, impact.
  - `debug-mode`: owaspName, description, recommendation, impact, prevention.
  - `server-all-interfaces`: severity, owaspName, description, recommendation, impact, prevention.
  Na amostra segura, nenhuma diferença.
- Pendências: interpretar falsos positivos e decidir as próximas regras apenas na etapa seguinte.
- Decisão: manter o comportamento dos scanners inalterado nesta etapa; divergências de metadados e achados não alinhados são registrados, não corrigidos.

### Comandos e resultados

- `Push-Location 'backend'; python scripts\metrics.py`: executado; imprime relatório textual e JSON.
- `python -m pytest tests\test_scanner.py tests\test_sample_metrics.py -q`: **11 passed, 19 subtests passed**.
- `python -m py_compile scripts\metrics.py tests\test_sample_metrics.py tests\samples\amostra_segura.py tests\samples\amostra_vulneravel.py`: **passou**.
- `Push-Location 'frontend'; npm ci`: **passou**, 0 vulnerabilidades reportadas.
- `npx vitest run --reporter=verbose --silent=false`: **3 arquivos e 9 testes passaram**. O Vitest reportou avisos preexistentes de largura nas tabelas do PDF.
