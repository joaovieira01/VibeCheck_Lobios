# Perguntas difíceis da banca

1. **Por que regex e não AST?**  
   O MVP prioriza baixo custo e cobertura de várias linguagens sem instalar
   parsers por linguagem. Isso perde contexto semântico e fluxo de dados; AST ou
   SAST dedicado é uma evolução, não algo que o scanner já faça.

2. **Qual é a taxa de falsos positivos?**  
   No corpus de 40 arquivos medido em 15/11/2026, foram 0/30 (0,0%) achados sem
   rótulo; recall 29/29 (100,0%) e precisão 30/30 (100,0%). Os rótulos foram
   corrigidos depois de observar resultados anteriores, então a medição não é
   independente nem generalizável para código real.

3. **O que o scanner não detecta bem?**  
   Fluxo entre arquivos, aliases/wrappers arbitrários, sanitizadores próprios e
   construções multilinha complexas. As linhas são limitadas a 1.000 caracteres
   e o scanner não executa o código.

4. **O upload ZIP é seguro?**  
   Há limites de tamanho compactado e expandido, contagem de arquivos,
   rejeição de caminhos inseguros e links simbólicos, leitura limitada e
   extração temporária. Isso reduz riscos conhecidos, mas não é prova de
   segurança absoluta; o parser e a infraestrutura ainda precisam ser mantidos.

5. **O que acontece com o código enviado à IA?**  
   Só é enviado quando a camada opcional está habilitada, ao endpoint escolhido.
   Há mascaramento heurístico de alguns segredos, mas ele não garante remoção de
   dados sensíveis. Os testes usam provedor falso; nenhum provedor real foi
   validado nesta revisão.

6. **Quanto custa executar?**  
   Não há custo de licença do scanner. Scrypt usa aproximadamente 128 MiB por
   operação; operações são serializadas por processo. IA e SCA online podem
   envolver limites ou custos dos respectivos provedores/serviços.

7. **Como escala para muitos usuários?**  
   O limitador de taxa é em memória por processo e o SQLite serve uma instância.
   Para múltiplas instâncias são necessários armazenamento e rate limit
   compartilhados, além de dimensionar memória pelos workers.

8. **Por que não existe app nativo de GitLab/Bitbucket?**  
   O que existe são templates de CI/CLI que geram relatórios. Webhooks, apps,
   permissões e comentários inline exigem integração e operação adicionais e
   ainda não foram implementados.

9. **O bot GitHub bloqueia o merge?**  
   Não. Ele publica comentários informativos. O CLI pode sair com código 1 por
   `--fail-on`, mas a política de branch protection precisa ser configurada
   separadamente.

10. **Como a checagem de dependências decide que um pacote não existe?**  
    Só um HTTP 404 do registry é tratado como inexistência. Timeout, erro de
    rede e 5xx deixam a checagem indisponível. A consulta online é opcional,
    limitada a 50 dependências por manifesto e não cobre todos os lockfiles ou
    dependências transitivas.

11. **A correção sugerida é aplicada automaticamente?**  
    Não. São sugestões determinísticas para um conjunto limitado de regras,
    mostradas como antes/depois para copiar e revisar. Uma sugestão pode exigir
    import, configuração ou ajuste específico do driver.

12. **Os números provam que está pronto para produção?**  
    Não. O backend passou 205 testes e o frontend 43; o benchmark mediu 40
    arquivos (29/29 recall, 30/30 precisão, 0/30 sem rótulo, em 0,058725 s).
    O teste de repositório analisou 500/500 arquivos sintéticos, 0 achados, em
    0,296 s, dependendo da máquina. Não houve validação em repositórios grandes
    reais nem execução dos pipelines GitLab/Bitbucket em suas plataformas.

