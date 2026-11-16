# Correções sugeridas

Cada achado pode incluir o campo opcional `suggestedFix`. O valor é uma lista
de objetos no mesmo índice de `locations` e `evidence`:

```json
{
  "suggestedFix": [
    {
      "before": "    DEBUG = True",
      "after": "    DEBUG = False",
      "explanation": "Mantenha o modo de depuração desativado."
    }
  ]
}
```

`before` preserva a linha original, incluindo indentação e aspas. `after` é o
trecho para copiar no lugar; pode conter mais de uma linha. A lista só é
incluída quando há uma correção determinística para todas as ocorrências do
achado. Se o scanner não puder sugerir uma alteração segura, o campo é omitido.
Históricos antigos sem esse campo continuam válidos.

As sugestões são heurísticas, não patches aplicados automaticamente. Revise o
diff e adapte-o ao projeto. Alguns exemplos dependem de configuração adicional:
variáveis de ambiente precisam ser definidas, `os`/`ast`/`secrets`/`crypto` podem
precisar ser importados, e o placeholder SQL precisa corresponder ao driver. Para SQL,
uma sugestão só é gerada quando o driver pode ser identificado no código.
A troca de hash por scrypt armazena o salt junto do hash; a verificação deve
recuperar e reutilizar esse salt. `ast.literal_eval` e `JSON.parse` aceitam
formatos menores que `eval`, então confirme que a entrada é dado nesse formato.

O scanner gera correções determinísticas para segredos fixos, SQL interpolado,
YAML inseguro, debug habilitado, validação TLS desabilitada, tokens com
aleatoriedade fraca, CORS curinga, bind em todas as interfaces, hash fraco de
senha e `eval`. No frontend, cada ocorrência mostra o antes/depois e oferece
**Copiar correção**. Na revisão de PR, sugestões de uma linha são publicadas no
formato `suggestion` do GitHub; alterações multilinha aparecem como código para
revisão manual.
