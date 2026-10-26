# Fluxos n8n

Coleção de workflows do [n8n](https://n8n.io), sanitizados para publicação (sem credenciais, tokens, IDs de conta ou dados pessoais).

## Como importar

1. No n8n: **Workflows → Import from File** e selecione um arquivo da pasta `workflows/`.
2. Nos nós marcados com `<<CRIAR CREDENCIAL ...>>`, crie/selecione sua própria credencial.
3. Substitua todo valor `<<PREENCHER>>` (IDs de planilhas, chats, chaves etc.) pelos seus.
4. Ative o fluxo.

## Como atualizar os fluxos (mantenedor)

1. No n8n, exporte cada fluxo (**⋯ → Download**) e salve o `.json` em `exportados/` (pasta ignorada pelo git).
2. Rode:
   ```
   python sanitizar_n8n.py
   ```
3. Leia o relatório: confira os itens em **REVISAR MANUALMENTE** e abra os arquivos gerados em `workflows/`.
4. Faça o commit apenas da pasta `workflows/`.
