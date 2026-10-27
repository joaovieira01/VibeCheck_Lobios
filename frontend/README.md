# VibeCheck — frontend

Interface React + TypeScript para análise estática heurística de segurança. Por
padrão, analisa no navegador sem API ou banco de dados; opcionalmente, pode usar
a API FastAPI do projeto quando `VITE_API_URL` estiver configurada.

A interface usa React + TypeScript + Vite, com Bootstrap 5 para grade e utilitários
responsivos e estilos próprios para identidade visual, animações e componentes.

## Executar localmente

Requisitos: Node.js 20.19+ e npm.

```powershell
npm install
npm run dev
```

Abra o endereço indicado pelo Vite (por padrão `http://localhost:5173`).

## Criar versão de produção

```powershell
npm run build
```

Os arquivos estáticos ficam em `dist/` e podem ser publicados no GitHub Pages ou
em outro host de frontend.

## O que o protótipo faz

- Analisa trechos colados ou arquivos de código de até 1 MB localmente no
  navegador. É possível selecionar ou arrastar até 20 arquivos, analisados um
  por vez; cada relatório fica disponível para consulta e exportação em PDF.
- Exibe evidências, linhas, severidade, referência CWE/OWASP, impacto, correção
  recomendada e prevenção.
- Baixa um relatório PDF estilizado, com resumo executivo, ordem sugerida de
  correção, cobertura heurística do OWASP Top 10:2025 e detalhes dos achados.
- Guarda um histórico demonstrativo neste navegador, via `localStorage`.

## Limitações e cobertura OWASP

As regras são heurísticas locais, não executam o código e não substituem uma
auditoria, SAST/DAST ou análise de dependências/CVEs. Categorias OWASP dependem
de contexto de aplicação; categoria sem alerta **não** significa aplicação
segura. A interface identifica explicitamente categorias que precisam de
revisão manual, como design inseguro, falhas de autenticação em fluxo,
dependências transitivas e configuração de infraestrutura.

A taxonomia acompanha o [OWASP Top 10:2025](https://top10.owasp.org/2025/). As
regras podem ser validadas e ampliadas usando o
[OWASP Benchmark](https://owasp.org/www-project-benchmark/) e os requisitos
verificáveis do [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/).
Mapear um padrão a uma categoria não significa cobertura completa da categoria.

## Usar a API FastAPI

O componente usa a interface `AnalysisService`, definida em
`src/services/analysisService.ts`. Sem `VITE_API_URL`, é usado
`LocalAnalysisService`; quando configurada, a implementação HTTP envia as
análises à API. Configure `VITE_API_URL=http://localhost:8000` em
`frontend/.env.local` e inicie também o backend. Cada arquivo do lote é enviado
separadamente e gravado como uma análise independente no histórico da conta.
