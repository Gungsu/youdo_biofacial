import os
import subprocess
from pathlib import Path

def generate_wireguard_keys():
    """Gera um novo par de chaves pública/privada do WireGuard."""
    try:
        # Gera a chave privada (wg genkey)
        private_key = subprocess.check_output(['wg', 'genkey']).decode('utf-8').strip()
        
        # Gera a chave pública a partir da privada (echo <private> | wg pubkey)
        pubkey_cmd = subprocess.Popen(['echo', private_key], stdout=subprocess.PIPE)
        public_key = subprocess.check_output(['wg', 'pubkey'], stdin=pubkey_cmd.stdout).decode('utf-8').strip()
        pubkey_cmd.wait()
        
        return private_key, public_key
    except FileNotFoundError:
        print("ERRO: O comando 'wg' (WireGuard Tools) não foi encontrado.")
        return None, None
    except Exception as e:
        print(f"ERRO: Falha ao gerar chaves WireGuard: {e}")
        return None, None
    
def restart_wireguard_service():
    """Reinicia o serviço WireGuard (wg0)."""
    try:
        # Usa 'wg-quick@wg0' para reiniciar a instância específica.
        # Necessita de permissão de superusuário (root)
        subprocess.run(['sudo', 'systemctl', 'restart', 'wg-quick@wg0'], check=True)
        print("INFO: Serviço WireGuard (wg0) reiniciado com sucesso.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERRO: Falha ao reiniciar o serviço WireGuard: {e}")
        return False