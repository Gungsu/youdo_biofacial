#!/bin/bash

# 1. Navegar até o diretório do projeto
cd /root/youdo_biofacial/

# 2. Puxar as atualizações do GitHub
git pull

# 3. Verificar se o pull foi bem-sucedido e se houve mudanças
# Se o status de saída do git pull for 0, mas o output indicar "Already up to date.",
# isso significa que não houve mudanças e não precisamos reiniciar.
if [ $? -eq 0 ] && ! grep -q "Already up to date" <<< "$(git status -uno)"; then
    echo "Código atualizado. Reiniciando o serviço Python..."
    # A forma de reiniciar depende de como o seu código Python está rodando.
    # Se você usa 'systemctl' (recomendado para serviços no Ubuntu):
    sudo systemctl restart apiyd.service
    
    # Se você roda manualmente o script principal (MENOS RECOMENDADO para produção):
    # pkill -f 'python seu_arquivo_principal.py'
    # nohup python seu_arquivo_principal.py &
else
    echo "Nenhuma atualização. Serviço não reiniciado."
fi