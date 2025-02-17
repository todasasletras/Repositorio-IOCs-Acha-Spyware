# Repositorio-IOCs-ferramenta-de-Verificacao-movel

Repositório e curadoria de indicadores de comprometimento do projeto "Ferramenta de verificação móvel".

## GitHub Action: Cópia dos arquivos STIX2 do MVT

Esta GitHub Action é responsável por copiar arquivos STIX2 de repositórios especificados no arquivo `indicators.yaml` do repositório `mvt-project/mvt-indicators`.

### Como funciona

1. A Action é acionada em pushs para a branch `main` ou manualmente.
2. Faz o checkout do repositório atual.
3. Faz o checkout do repositório `mvt-indicators`.
4. Instala as dependências necessárias (`python3-pip` e `pyyaml`).
5. Faz o parsing do arquivo `indicators.yaml` e baixa os arquivos especificados dos repositórios GitHub.
6. Salva os arquivos baixados em uma estrutura de diretórios baseada no proprietário do repositório dentro da pasta `mvt`.
7. Comita e faz o push das mudanças para o repositório atual.

### Contribuições

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues e pull requests.

### Licença

Este projeto está licenciado sob a licença Mozilla Public License Version 2.0. Veja o arquivo LICENSE para mais detalhes.
