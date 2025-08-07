# Repositorio-IOCs-ferramenta-de-Verificacao-movel

Repositório e curadoria de indicadores de comprometimento do projeto "Ferramenta de verificação móvel".


## GitHub Action: Geração e Atualização Automática do STIX2 do Todas as Letras

Esta GitHub Action executa semanalmente (todo domingo à 00:00 UTC) o script `Scripts/generate_stix.py`, que consulta a API do MalwareBazaar, gera o arquivo STIX2 com os indicadores de comprometimento para dispositivos móveis e o salva em `mvt/Todas_as_letras/todas_as_letras_mobile_iocs.v1.stix2`.

### Como funciona

1. A Action é acionada automaticamente por agendamento semanal ou manualmente via GitHub.
2. Faz o checkout do repositório.
3. Instala as dependências Python listadas em `Scripts/requirements.txt`.
4. Executa o script `Scripts/generate_stix.py`.
5. O script utiliza a variável de ambiente secreta `MALWAREBAZAAR_API_KEY` (configure em Settings > Secrets and variables > Actions).
6. O arquivo gerado é movido para `mvt/Todas_as_letras/` e commitado automaticamente no repositório.

### Como configurar a chave da API

1. Obtenha sua chave de API no [MalwareBazaar](https://bazaar.abuse.ch/api/).
2. No GitHub, acesse Settings > Secrets and variables > Actions.
3. Adicione um novo secret chamado `MALWAREBAZAAR_API_KEY` com o valor da sua chave.

### Estrutura esperada do arquivo gerado

O arquivo gerado será salvo como:

```
mvt/Todas_as_letras/todas_as_letras_mobile_iocs.v1.stix2
```

### Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests.

### Licença

Este projeto está licenciado sob a licença Mozilla Public License Version 2.0. Veja o arquivo LICENSE para mais detalhes.
