# Benchmark independente do scanner

## Metodologia

O benchmark contém 40 arquivos curtos: 20 Python e 20 exemplos do ecossistema
JavaScript (19 arquivos `.js`/`.ts` e um `package.json`). São 28 arquivos com
uma linha vulnerável rotulada e 12 equivalentes seguros. Os exemplos cobrem
segredos, SQL, autenticação/autorização, criptografia, XSS, SSRF, configuração,
desserialização, logging e dependências. Credenciais são fictícias.

O corpus e os rótulos foram escritos sem consultar as regras do scanner nem as
amostras existentes. O script `backend/scripts/benchmark.py` lê os arquivos
listados em `backend/tests/benchmark/labels.json`, executa o scanner local e
grava os resultados em `backend/tests/benchmark/report.json`. Não há chamadas
de rede. Os arquivos `bench_*` não seguem o padrão de coleta de testes do
pytest.

Uma detecção conta como correta se coincide com o arquivo, a linha e a
categoria OWASP rotulados. Recall é a proporção de linhas vulneráveis
detectadas nessa categoria. Precisão é a proporção dos achados que coincidem
com um rótulo. A taxa de falsos positivos é achados sem rótulo correspondente
divididos pelo total de achados. Tempo é medido localmente durante a execução
do scanner sobre o corpus; não representa análise de um repositório grande.

## Resultado observado

| Métrica | Resultado |
|---|---:|
| Recall total | 23/28 (82,1%) |
| Precisão | 24/25 (96,0%) |
| Taxa de falsos positivos | 1/25 (4,0%) |
| Tempo total para 40 arquivos | 0,059457 s |
| Meta de FP abaixo de 15% nesta amostra | Atingida |
| Meta de menos de 2 minutos nesta amostra | Atingida |

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

Os tempos individuais por arquivo, além das métricas e dos achados, estão no
`report.json` gerado pelo script.

## Erros observados

### Falsos negativos

| Arquivo | Linha | Categoria | Caso |
|---|---:|---|---|
| `bench_js_01.ts` | 1 | A04 | Chave Stripe fictícia |
| `bench_js_07.ts` | 3 | A01 | SSRF com URL obtida da solicitação |
| `bench_js_14.js` | 3 | A05 | HTML de resposta com conteúdo da solicitação |
| `bench_py_06.py` | 9 | A01 | SSRF com destino atribuído a variável |
| `bench_py_12.py` | 10 | A01 | Caminho de arquivo concatenado com parâmetro |

### Falso positivo

| Arquivo | Linha | Regra reportada | Caso |
|---|---:|---|---|
| `bench_js_20.js` | 2 | `insecure-cookie` (A02) | As opções seguras do cookie estão distribuídas em várias linhas |

## Limitações

O corpus é pequeno e foi escrito pela equipe; portanto, apesar da intenção de
independência em relação às regras e amostras internas, não equivale a uma
avaliação cega por terceiros. Cada arquivo tem um único rótulo principal, e a
comparação considera linha e categoria, não a exploração em runtime. Os
resultados não são generalizáveis para outras linguagens, frameworks,
distribuições de código ou repositórios. O tempo depende do hardware e do
tamanho reduzido dos arquivos; não demonstra o desempenho em um repositório
completo. As metas observadas nesta amostra não devem ser apresentadas como
garantia de produção.
