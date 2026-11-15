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

## Após correções (não independente)

Esta execução ocorreu depois de as regras terem sido ajustadas com base nos
erros observados no benchmark. Portanto, **não é uma avaliação independente**.
O corpus e `labels.json` foram mantidos sem alterações durante esta etapa.

| Métrica | Baseline publicado | Após correções |
|---|---:|---:|
| Recall total | 23/28 (82,1%) | 27/28 (96,4%) |
| Precisão | 24/25 (96,0%) | 28/30 (93,3%) |
| Achados sem rótulo / taxa de falsos positivos | 1/25 (4,0%) | 2/30 (6,7%) |
| Tempo total para 40 arquivos | 0,059457 s | 0,097711 s |
| Recall A01 | 3/6 (50,0%) | 5/6 (83,3%) |
| Recall A02 | 2/2 (100,0%) | 2/2 (100,0%) |
| Recall A03 | 1/1 (100,0%) | 1/1 (100,0%) |
| Recall A04 | 5/6 (83,3%) | 6/6 (100,0%) |
| Recall A05 | 7/8 (87,5%) | 8/8 (100,0%) |
| Recall A07 | 2/2 (100,0%) | 2/2 (100,0%) |
| Recall A08 | 2/2 (100,0%) | 2/2 (100,0%) |
| Recall A09 | 1/1 (100,0%) | 1/1 (100,0%) |

O caso de travessia de diretório é encontrado no código em
`bench_py_12.py:9`, mas o rótulo atual aponta para a linha 10. Como a métrica
exige correspondência exata de linha, o relatório contabiliza essa detecção
como um achado sem rótulo e mantém uma vulnerabilidade como não detectada.
O rótulo foi preservado conforme o requisito de não modificar o benchmark.

O outro achado sem rótulo é `ssrf` em `bench_py_14.py:6`, na mesma chamada que
desativa a verificação TLS e está rotulada como A04. A chamada usa uma URL
originada da requisição; o benchmark possui somente um rótulo principal por
arquivo, então a detecção adicional de SSRF é contabilizada como FP pelo
formato de avaliação, embora não seja um falso positivo semântico comprovado.
O achado rotulado `tls-disabled` nessa mesma linha foi contado como correto.

### Execução reproduzida em 15/11/2026

Com `Python 3.12.10` e o código atual, `python scripts/benchmark.py` registrou:

| Métrica | Resultado observado |
|---|---:|
| Arquivos no corpus | 40 (28 vulneráveis e 12 seguros) |
| Recall | 27/28 (96,4%) |
| Precisão | 28/30 (93,3%) |
| Achados sem rótulo / taxa segundo a comparação exata | 2/30 (6,7%) |
| Tempo total | 0,063674 s |

Recall por categoria: A01 **5/6**, A02 **2/2**, A03 **1/1**, A04 **6/6**,
A05 **8/8**, A07 **2/2**, A08 **2/2** e A09 **1/1**. O falso negativo e os
dois achados sem correspondência são os descritos acima: desencontro de linha
em `bench_py_12.py` e achado SSRF adicional em `bench_py_14.py`.

O nome “benchmark independente” descreve a origem do corpus (criado sem
consultar as regras), não uma avaliação externa cega. As regras já haviam sido
ajustadas antes desta execução; portanto, o resultado atual **não é
independente das correções** e não deve ser apresentado como recall em produção.

`python scripts/bench_repo.py` analisou **500/500 arquivos sintéticos**, com
**0 achados**, em **0,252 s**. O script cria 250 arquivos Python e 250
TypeScript pequenos e seguros. Esse resultado mede apenas esse repositório
artificial; não demonstra desempenho ou cobertura em repositórios reais.

### Erros após correções

| Tipo segundo comparação exata com rótulos | Arquivo | Linha | Detalhe |
|---|---|---:|---|
| Não detectado | `bench_py_12.py` | 10 | Rótulo A01 de path traversal; a regra detecta o código na linha 9 |
| Achado sem rótulo | `bench_py_12.py` | 9 | `path-traversal`, desencontro de uma linha entre código e rótulo |
| Achado sem rótulo | `bench_py_14.py` | 6 | `ssrf` adicional na linha rotulada por `tls-disabled` (A04) |

As opções seguras do cookie em `bench_js_20.js` deixaram de produzir o achado
do baseline.

### Histórico das duas execuções anteriores

A primeira execução registrou 22/28 de recall e 2/25 achados sem rótulo; a
segunda, publicada acima como baseline, registrou 23/28 e 1/25. Após observar
a primeira execução, foi corrigido em `labels.json` o rótulo de
`bench_py_01.py`, da linha 3 para a linha 4. Nenhum conteúdo-fonte dos exemplos
do corpus foi alterado entre essas duas execuções. A renomeação do manifesto
para `package.json` ocorreu antes da primeira medição. Assim, a segunda
execução manteve os arquivos-fonte, mas não manteve os rótulos originais da
primeira execução.

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
