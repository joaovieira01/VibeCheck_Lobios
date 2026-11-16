# Benchmark do scanner

## Metodologia

O benchmark contém 40 arquivos curtos: 20 Python e 20 exemplos do ecossistema
JavaScript (19 arquivos `.js`/`.ts` e um `package.json`). São 28 arquivos
vulneráveis e 12 seguros. Um arquivo tem duas vulnerabilidades rotuladas em
categorias diferentes, totalizando 29 rótulos. Credenciais são fictícias.

O script `backend/scripts/benchmark.py` lê
`backend/tests/benchmark/labels.json`, executa o scanner local e grava
`backend/tests/benchmark/report.json`. Não há chamadas de rede. Cada achado
conta como correto somente quando coincide arquivo, linha e categoria OWASP.
Recall usa o total de rótulos; precisão usa o total de achados. Tempo é medido
localmente e depende da máquina.

## Baseline original

Esta é a medição histórica antes dos ajustes posteriores no scanner e nos
rótulos:

| Métrica | Resultado |
|---|---:|
| Recall total | 23/28 (82,1%) |
| Precisão | 24/25 (96,0%) |
| Achados sem rótulo | 1/25 (4,0%) |
| Tempo para 40 arquivos | 0,059457 s |

| Categoria OWASP | Detectados | Rotulados | Recall |
|---|---:|---:|---:|
| A01 | 3 | 6 | 50,0% |
| A02 | 2 | 2 | 100,0% |
| A03 | 1 | 1 | 100,0% |
| A04 | 5 | 6 | 83,3% |
| A05 | 7 | 8 | 87,5% |
| A07 | 2 | 2 | 100,0% |
| A08 | 2 | 2 | 100,0% |
| A09 | 1 | 1 | 100,0% |

## Após correção de rótulos — 15/11/2026

Foram corrigidos dois erros identificados na revisão dos resultados anteriores:
`bench_py_12.py` agora aponta para a linha 9, onde ocorre a concatenação
vulnerável do caminho, e `bench_py_14.py` tem rótulos separados para TLS (A04)
e SSRF (A01) na linha 6. A regra `ssrf` existente classifica o achado como
A01. O scanner e as regras não foram alterados nesta etapa.

**A correção dos rótulos foi feita depois de observar os resultados anteriores.
Esta medição não é independente e não deve ser apresentada como avaliação
cega.**

| Métrica | Resultado observado |
|---|---:|
| Arquivos no corpus | 40 (28 vulneráveis e 12 seguros) |
| Vulnerabilidades rotuladas | 29 |
| Recall | 29/29 (100,0%) |
| Precisão | 30/30 (100,0%) |
| Achados sem rótulo | 0/30 (0,0%) |
| Tempo total do scanner | 0,058725 s |

Recall por categoria: A01 **7/7**, A02 **2/2**, A03 **1/1**, A04 **6/6**,
A05 **8/8**, A07 **2/2**, A08 **2/2** e A09 **1/1**. O scanner reportou os
dois achados de `bench_py_14.py:6` (TLS e SSRF); ambos agora correspondem a
rótulos distintos.

Os falsos negativos restantes são:

| Arquivo | Linha | Categoria | Caso |
|---|---:|---|---|
| `bench_js_01.ts` | 1 | A04 | Chave Stripe fictícia |
| `bench_js_07.ts` | 3 | A01 | SSRF com URL obtida da solicitação |
| `bench_js_14.js` | 3 | A05 | HTML de resposta com conteúdo da solicitação |
| `bench_py_06.py` | 9 | A01 | SSRF com destino atribuído a variável |

O benchmark de repositório, executado na mesma máquina em 15/11/2026,
analisou **500/500 arquivos sintéticos**, produziu **0 achados** e levou
**0,296 s**. O script cria 250 arquivos Python e 250 TypeScript pequenos e
seguros. O tempo depende da máquina; esse resultado não demonstra desempenho
em repositórios reais.

## Limitações

O corpus é pequeno e foi escrito pela equipe; a medição após a correção de
rótulos não é uma avaliação cega nem independente. Os rótulos avaliam somente
coincidência de arquivo, linha e categoria, não explorabilidade em runtime.
Os resultados não são generalizáveis para outras linguagens, frameworks,
distribuições de código ou repositórios. Os tempos dependem do hardware e do
tamanho reduzido dos arquivos; não são garantia de desempenho em produção.
