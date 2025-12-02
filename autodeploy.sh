#!/bin/bash

# 1. Navegar até o diretório do projeto
cd /root/youdo_biofacial/

# 2. Forçar a limpeza do ambiente antes de puxar as atualizações
TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

echo "=================================================="
echo "DEPLOY INICIADO: $TIMESTAMP"
echo "=================================================="

echo "Iniciando limpeza forçada do ambiente..."

# Desfaz TODAS as alterações locais não comitadas para a versão do HEAD (último commit)
# Isso resolve o erro "Your local changes would be overwritten"
git reset --hard HEAD

# Remove arquivos e diretórios não rastreados (u: files, d: directories, f: force)
# Isso resolve o erro "untracked files would be overwritten"
git clean -df

# 3. Puxar as atualizações do GitHub
echo "Puxando atualizações do GitHub..."
GIT_OUTPUT=$(git pull)
EXIT_CODE=$?

# 4. Verificar o resultado do pull
echo "$GIT_OUTPUT"

# Se o pull foi bem-sucedido (código de saída 0) E o output não indica que está 'Already up to date'
if [ $EXIT_CODE -eq 0 ] && ! echo "$GIT_OUTPUT" | grep -q "Already up to date"; then
    echo "Código atualizado. Reiniciando o serviço Python..."
    
    # Reiniciar o serviço
    sudo systemctl restart apiyd.service
    
else
    # O git pull pode retornar a mensagem "Already up to date" ou ter falhado por outros motivos
    # (embora o reset e clean resolvam os problemas mais comuns).
    echo "Nenhuma atualização ou erro não resolvido. Serviço não reiniciado."
fi