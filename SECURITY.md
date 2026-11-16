# Política de segurança

O VibeCheck é uma ferramenta de apoio à revisão de segurança, em estágio de MVP. Esta política descreve como relatar uma vulnerabilidade, o que o projeto já faz para se proteger e o que ainda não cobre.

## Versões suportadas

Só a versão mais recente da branch `main` recebe correções de segurança.

## Como relatar uma vulnerabilidade

**Não abra uma issue pública** com detalhes de uma vulnerabilidade.

Use o relato privado do GitHub: na página do repositório, abra **Security → Report a vulnerability** (o recurso precisa estar ativado em *Settings → Code security*). Se não estiver disponível, contate o mantenedor pelo perfil [@joaovieira01](https://github.com/joaovieira01) pedindo um canal privado, sem descrever a falha em público.

Inclua, se possível:

- o componente afetado (backend, frontend, scanner, workflow de PR, Docker);
- passos para reproduzir e o resultado esperado;
- o impacto que você enxerga;
- versão ou commit testado.

Não envie segredos reais, dados pessoais ou código de terceiros nos relatos.

**Prazos.** O projeto é mantido por poucas pessoas. A meta é confirmar o recebimento em até 7 dias e informar o andamento da correção. Não há programa de recompensas.

## Escopo

Dentro do escopo: este repositório (API FastAPI, scanner, frontend, scripts, workflows e configuração Docker).

Fora do escopo: vulnerabilidades em serviços de terceiros (provedores de IA, OSV, PyPI, npm, GitHub), ataques de negação de serviço volumétricos, engenharia social e testes contra a instância de demonstração que causem carga ou acessem dados de outras pessoas.

## Controles implementados

**Autenticação e sessões**
- Senhas com scrypt (`N=2^17`, `r=8`), salt aleatório e comparação em tempo constante; os parâmetros ficam no hash e permitem reforço gradual (rehash no login).
- Tokens de sessão e de recuperação de senha com 256 bits aleatórios. O banco guarda apenas o SHA-256 deles.
- Login com resposta e tempo equivalentes para e-mail inexistente, e recuperação de senha com mensagem idêntica exista a conta ou não.
- Token de recuperação de uso único, com expiração; redefinir a senha encerra todas as sessões da conta.
- Limites de taxa em login (por IP e por IP+e-mail), cadastro, recuperação, análise e upload de repositório.

**API**
- Consultas SQL parametrizadas.
- Limite de tamanho de corpo (`Content-Length` obrigatório em `POST`), de tamanho de código, de comprimento de linha e orçamento de tempo por análise, para conter ReDoS e abuso de CPU.
- CORS com lista explícita de origens; em produção a inicialização rejeita `*`.
- Cabeçalhos de segurança em todas as respostas (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), `Cache-Control: no-store` em `/api/*` e HSTS quando `VIBECHECK_ENV=production`.
- Erros de validação não devolvem a estrutura interna do Pydantic.
- Em produção, a inicialização recusa seed de usuário demo e senha de banco vazia ou de exemplo.

**Análise de arquivos e repositórios**
- O código analisado nunca é executado.
- ZIPs: limites de tamanho compactado e descompactado e de quantidade de arquivos; rejeição de links simbólicos, caminhos absolutos, `..` e entradas duplicadas (path traversal e zip bomb).
- Arquivos binários, acima de 1 MB ou com codificação inválida são ignorados.

**Camada de IA (opcional, desligada por padrão)**
- Segredos e credenciais são mascarados antes do envio; o código é tratado como dado, não como instrução.
- Endpoint exige HTTPS (exceto `localhost`); a chave vai em variável de ambiente, nunca na URL.
- A triagem nunca remove um achado da lista, e descartes de achados críticos exigem confiança alta.

**CI/CD**
- O workflow de revisão de PR usa `pull_request_target`, faz checkout apenas da revisão base confiável, **nunca executa o código do PR** e usa permissões mínimas (`contents: read`, `pull-requests: write`).
- O workflow de testes (`ci.yml`) roda só com leitura e sem segredos.
- Dependabot acompanha pip, npm, GitHub Actions e Docker.

## Limitações conhecidas

Estas limitações são conhecidas e não devem ser tratadas como surpresa em um relato:

- **O scanner é heurístico.** Ele não substitui auditoria, teste de intrusão ou SAST completo, e pode ter falsos positivos e negativos. Veja [docs/LIMITACOES.md](docs/LIMITACOES.md).
- **Token de sessão no `localStorage` do navegador.** Qualquer XSS no frontend poderia lê-lo. O frontend não usa `dangerouslySetInnerHTML` nem `innerHTML` (o React escapa o conteúdo por padrão), mas não há CSP configurada no frontend hospedado.
- **Rate limit em memória, por processo.** Em várias instâncias ou atrás de proxy sem `--proxy-headers`, o limite não é compartilhado nem enxerga o IP real.
- **Não há MFA nem verificação de e-mail no cadastro.**
- **O histórico guarda evidências.** Uma linha com segredo detectado pode ser persistida no banco; proteja o banco e o acesso ao histórico.
- **Scrypt usa cerca de 128 MiB por operação**, e o semáforo é por processo; dimensione a memória por worker.
- **`docker-compose.yml` é de desenvolvimento** (usa `--reload`, publica portas apenas em `127.0.0.1`). Não há configuração de produção validada neste repositório.
- A conta demo (`VIBECHECK_SEED_DEMO_USER=true`) usa credencial pública; nunca a habilite em ambiente exposto.

## Checklist para quem for hospedar

- [ ] `VIBECHECK_ENV=production`
- [ ] Senhas fortes e únicas para MySQL e conta da aplicação (sem privilégios administrativos)
- [ ] `VIBECHECK_CORS_ORIGINS` apenas com o domínio real do frontend
- [ ] HTTPS na frente da API, com `uvicorn --proxy-headers` e `--forwarded-allow-ips` restritos ao proxy
- [ ] Banco sem exposição pública; backups cifrados
- [ ] Limitador de requisições compartilhado se houver mais de uma instância
- [ ] CSP e demais cabeçalhos no host do frontend
- [ ] Revisar os termos do provedor antes de ativar `AI_ENABLED`
- [ ] Nunca commitar `.env` ou chaves de API; rotacionar qualquer chave que tenha vazado
- [ ] Ativar *branch protection* e o relato privado de vulnerabilidades no GitHub
