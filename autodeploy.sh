#!/bin/bash

# 1. Navegar até o diretório do projeto
cd /root/youdo_biofacial/

# 2. Puxar as atualizações do GitHub
GIT_OUTPUT=$(git pull)
EXIT_CODE=$?

# 3. Verificar se o pull foi bem-sucedido e se houve mudanças
echo "$GIT_OUTPUT"
# Se o status de saída do git pull for 0, mas o output indicar "Already up to date.",
# isso significa que não houve mudanças e não precisamos reiniciar.
if [ $EXIT_CODE -eq 0 ] && ! echo "$GIT_OUTPUT" | grep -q "Already up to date"; then
    echo "Código atualizado. Reiniciando o serviço Python..."
    
    # Reiniciar o serviço
    sudo systemctl restart apiyd.service
    
else
    echo "Nenhuma atualização. Serviço não reiniciado."
fi