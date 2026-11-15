# GitHub Actions

O repositório VibeCheck já inclui a revisão de Pull Requests em
[`.github/workflows/vibecheck-pr-review.yml`](../../.github/workflows/vibecheck-pr-review.yml).
Ela roda em Pull Requests não rascunho e publica comentários com os achados nas linhas novas.

O workflow atual, em resumo:

```yaml
name: VibeCheck

on:
  pull_request_target:
    types: [opened, reopened, synchronize, ready_for_review]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-review:
    if: github.event.pull_request.draft == false
    runs-on: ubuntu-latest
    steps:
      - name: Check out trusted base revision
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Review changed code
        run: python backend/scripts/github_pr_review.py
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPOSITORY: ${{ github.repository }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}
```

No próprio projeto, mantenha esse arquivo em `.github/workflows/` para ativar a
integração. Ele usa o script deste repositório; não é uma GitHub Action reutilizável
para instalação direta em projetos externos. Para usar o scanner em outro pipeline,
consulte [`docs/INTEGRACOES.md`](../../docs/INTEGRACOES.md) e execute o CLI.
