import os
import subprocess
from pathlib import Path
import re

WIREGUARD_CONF_PATH = Path('/etc/wireguard/wg0.conf')
WIREGUARD_PUB_PATH = Path('/etc/wireguard/wg0_pub')
WG_INTERFACE_NAME = 'wg0'
WG_FILENAME = "wg0.conf"

def generate_wireguard_keys(novo_ip_VPN):
    """Gera um novo par de chaves pública/privada do WireGuard."""
    try:
        # Gera a chave privada (wg genkey)
        private_key = subprocess.check_output(['wg', 'genkey']).decode('utf-8').strip()
        
        # Gera a chave pública a partir da privada (echo <private> | wg pubkey)
        pubkey_cmd = subprocess.Popen(['echo', private_key], stdout=subprocess.PIPE)
        public_key = subprocess.check_output(['wg', 'pubkey'], stdin=pubkey_cmd.stdout).decode('utf-8').strip()
        pubkey_cmd.wait()
        print(f"INFO: Chaves WireGuard geradas com sucesso.")
        print(f"Private Key: {private_key}")
        print(f"Public Key: {public_key}")
        altera_wg0(private_key,public_key,novo_ip_VPN)
        return private_key, public_key
    except FileNotFoundError:
        print("ERRO: O comando 'wg' (WireGuard Tools) não foi encontrado.")
        return None, None
    except Exception as e:
        print(f"ERRO: Falha ao gerar chaves WireGuard: {e}")
        return None, None
    
def restart_wireguard_service():
    """Reinicia o serviço WireGuard (wg0)."""
    """LEMBRAR DE ALTERAR O NOME DO HOST PARA centralmrd[numero]"""
    try:
        # Usa 'wg-quick@wg0' para reiniciar a instância específica.
        # Necessita de permissão de superusuário (root)
        subprocess.run(['sudo', 'systemctl', 'restart', 'wg-quick@wg0'], check=True)
        print("INFO: Serviço WireGuard (wg0) reiniciado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERRO: Falha ao reiniciar o serviço WireGuard: {e}")
        return False

def stop_wireguard_service():
    """Reinicia o serviço WireGuard ({VPCONF})."""
    """LEMBRAR DE ALTERAR O NOME DO HOST PARA centralmrd[numero]"""
    try:
        # Usa 'wg-quick@{VPCONF}' para reiniciar a instância específica.
        # Necessita de permissão de superusuário (root)
        subprocess.run(['systemctl', 'stop', f'wg-quick@{WG_INTERFACE_NAME}'], check=True)
        print(f"INFO: Serviço WireGuard ({WG_FILENAME}) parado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERRO: Falha ao parar o serviço WireGuard: {e}")
        return False

def altera_wg0(private_key,public_key,novo_ip_VPN):
    makeResp = [{}]
    response_data = {
        "new_public_key": "0",
        "new_server_ip": "0",
        "status": "Aguardando reinício do serviço..."
    }
    """Para o serviço WireGuard (wg0)."""
    stop_wireguard_service()
    
    try:
        # Lendo o arquivo atual
        if not WIREGUARD_CONF_PATH.exists():
            return (f"Arquivo de configuração não encontrado: {WIREGUARD_CONF_PATH}")
            
        conf_content = WIREGUARD_CONF_PATH.read_text()
        
        # --- Lógica de Substituição ---
        
        # 3a. Substituir a PrivateKey da Interface
        # Regex para encontrar "PrivateKey = [CHAVE ANTIGA]" e substituir.
        conf_content = re.sub(
            r'^PrivateKey\s*=\s*.*$', 
            f'PrivateKey = {private_key}', 
            conf_content, 
            flags=re.MULTILINE
        )
        
        # 3b. Substituir o Address da Interface pelo novo IP
        ipcom24 = f"{novo_ip_VPN}/24"
        
        conf_content = re.sub(
            r'^Address\s*=\s*.*$', 
            f'Address = {ipcom24}',
            conf_content, 
            flags=re.MULTILINE
        )
              
        # Salvando o backup (melhor prática)
        backup_path = WIREGUARD_CONF_PATH.with_suffix('.conf.bak')
        WIREGUARD_CONF_PATH.rename(backup_path)
        
        # Escrevendo o novo arquivo
        WIREGUARD_CONF_PATH.write_text(conf_content)
        
        WIREGUARD_PUB_PATH.write_text(public_key)
        
    except Exception as e:
        response_data["status"] = f"ERRO ao salvar arquivo: {e}. Verifique permissões."
        makeResp.append(response_data)
        return "ERROR01"

    # 4. Reiniciar o serviço wireguard
    restart_wireguard_service()
    #if vpn.restart_wireguard_service():
    response_data["status"] = "SUCESSO: Chave atualizada e solicite reiniciar o serviço reiniciado."
    makeResp.append(response_data)
    return True