import netifaces
import schedule
import subprocess
from pymongo import MongoClient
import ydAPI1 as yd
import time
import re
from datetime import datetime, timezone, timedelta
import nmap
import socket
import scapy.all as scapy
import ipaddress
import requests as RQfunction

# MongoDB connection details
MONGO_HOST = '192.168.101.1'
MONGO_PORT = 27017
DATABASE_NAME = 'biofacial'
COLLECTION_EQ_NAME = 'equipamentos_2_1' # Replace with your actual collection name
COLLECTION_CT_NAME = 'centrais_2_1' # Replace with your actual collection name

client = MongoClient(
            MONGO_HOST,
            MONGO_PORT,
            serverSelectionTimeoutMS=5000,
            directConnection=True
        )

onFalha = False
def myData(db_client: MongoClient):
    # Função que mantem atualizada o servidor quanto a "meu" ip local
    dataResp = {"ip_local": "", "ip_vpn": "", "device_id": "", "mac": "", "netMask": ""}
    
    try:
        # Pega a interface de rede padrão (geralmente a principal conexão à internet)
        default_gateway_interface = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, (None, None))[1]

        # Itera sobre todas as interfaces de rede disponíveis no sistema
        for interface in netifaces.interfaces():
            # Obtém os endereços associados a esta interface
            enderecos = netifaces.ifaddresses(interface)
            
            # Focamos nos endereços IPv4, que são os mais comuns para este caso
            if socket.AF_INET in enderecos:
                info_ipv4 = enderecos[socket.AF_INET][0]
                ip = info_ipv4.get('addr')
                mascara = info_ipv4.get('netmask')
                interface_obj = ipaddress.IPv4Interface(f'{ip}/{mascara}')
                notacao_cidr = f"/{interface_obj.network.prefixlen}"

                if not ip or not mascara:
                    continue

                if ip == '127.0.0.1':
                    continue

                if ip and ip.startswith('192.168.101.'):
                    dataResp["ip_vpn"] = ip
                
                elif interface == default_gateway_interface:
                    dataResp["ip_local"] = ip
                    dataResp["netMask"] = notacao_cidr
        
        db = db_client[DATABASE_NAME]
        centrais_collection = db[COLLECTION_CT_NAME]
        # Busca a central com o IP VPN
        dataWithPort = dataResp['ip_vpn'] + ":557"
        central = centrais_collection.find_one({"ip_VPN": dataWithPort})
        dataResp["device_id"] = central["device_id"] if central else None
        
        if central:
            iplocalecidr = dataResp["ip_local"] + dataResp["netMask"]
            resultado = centrais_collection.update_one(
                {"_id": central["_id"]},
                {"$set": {"ip_local": iplocalecidr}}
            )

    except Exception as e:
        print(f"❌ Ocorreu um erro ao buscar as interfaces: {e}")
    return dataResp

def listaMacEqs(db_client: MongoClient = client):
    """
    Varre a rede usando ARP para encontrar dispositivos e retorna uma lista de dicionários.
    retorna: {
        "configurados": [{"ip": "", "mac": "", "hostname": "", "device_id": ""}],
        "novos": [{"ip": "", "mac": "", "hostname": "", "device_id": ""}]
    }
    """
    # Cria um pacote de requisição ARP para o alvo especificado (ex: '192.168.1.0/24')
    data = myData(client)
    ip_local = data["ip_local"]
    device_id = data["device_id"]
    eqs_encontrados = {"configurados": [], "novos": []}
    
    if not ip_local:
        print("❌ Não foi possível determinar o IP local. Abortando varredura.")
        return eqs_encontrados

    try:
        # strict=False permite criar o objeto a partir de um IP de host
        rede = ipaddress.ip_network(f"{ip_local}/24", strict=False)
        alvo_rede = str(rede) # Garante o formato "192.168.0.0/24"
    except ValueError:
        print(f"❌ IP local '{ip_local}' inválido para criar uma rede.")
        return eqs_encontrados

    requisicao_arp = scapy.ARP(pdst=alvo_rede)
    frame_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    pacote_arp_broadcast = frame_broadcast / requisicao_arp
    
    lista_respondidos, _ = scapy.srp(pacote_arp_broadcast, timeout=2, verbose=False)
    
    db = db_client[DATABASE_NAME]
    eq_collection = db[COLLECTION_EQ_NAME]
    
    for elemento in lista_respondidos:
        # A resposta contém o IP (psrc) e o MAC (hwsrc) do dispositivo
        ip_dispositivo = elemento[1].psrc
        mac_dispositivo = elemento[1].hwsrc
        hostname = ""
        
        # Tenta resolver o hostname a partir do IP (pode falhar)
        try:
            log = yd.payLogin(ip_dispositivo)
            print(f"GERAL IP: {ip_dispositivo:<15} MAC: {mac_dispositivo:<17}")
            upBD = False
            if log == 1:
                info = yd.eqInfo(ip_dispositivo)
                hostname = info["network"]["device_hostname"]
                eqs_encontrados["configurados"].append({
                    "ip": ip_dispositivo,
                    "mac": mac_dispositivo,
                    "hostname": hostname,
                    "device_id": info["device_id"]
                })
                #print(f"CONF: IP: {ip_dispositivo:<15} MAC: {mac_dispositivo:<17} Hostname: {hostname}")
                yd.logout(ip_dispositivo)
                upBD = True
                
            else:
                log = yd.payLoginOLD(ip_dispositivo)
                if log == 1:
                    info = yd.eqInfo(ip_dispositivo)
                    hostname = info["network"]["device_hostname"]
                    eqs_encontrados["novos"].append({
                        "ip": ip_dispositivo,
                        "mac": mac_dispositivo,
                        "hostname": hostname,
                        "device_id": info["device_id"]
                    })
                    print(f"NEW IP: {ip_dispositivo:<15} MAC: {mac_dispositivo:<17} Hostname: {hostname}")
                    yd.logout(ip_dispositivo)
                    upBD = True
                # Verifica se o equipamento já está no banco de dados
            if upBD:
                existing_eq = eq_collection.find_one({"device_id": info["device_id"]})
                if existing_eq:
                    # Atualiza o IP e MAC se já existir
                    eq_collection.update_one(
                        {"device_id": info["device_id"]},
                        {"$set": {"ip": ip_dispositivo, "mac": mac_dispositivo, "device_hostname": hostname}}
                        )

            print("...")
        except:
            hostname = "Não resolvido"
            
        #print(f"IP: {ip_dispositivo:<15} MAC: {mac_dispositivo:<17} Hostname: {hostname}")
    return eqs_encontrados

def ajustarRelogioEqs(db_client: MongoClient = client):
    db = db_client[DATABASE_NAME]
    eq_collection = db[COLLECTION_EQ_NAME]
    meusDados = myData(client)
    # 1. Crie o filtro combinado
    filtro = {
        "central_id": meusDados["device_id"],
        "ip": {"$exists": True, "$ne": ""}
    }
    projecao = {"ip": 1, "_id": 0}
    cursor = eq_collection.find(filtro, projecao)
    print("Ajustando o relógio dos equipamentos...")
    for eq in cursor:
        log = yd.payLogin(eq['ip'])
        if log != 1:
            print(f"❌ Falha ao conectar no equipamento {eq['ip']}. Pulando ajuste de relógio.")
            onFalha = True
            continue
        yd.setTime(eq['ip'])
        yd.logout(eq['ip'])
        print (f"Ajustando o relógio do equipamento: {eq['ip']}")
           
    return "SUCCESS"

def corrigirRelogio(valorEmHHMM):
    hora, minuto = map(int, valorEmHHMM.split(':'))
    deslocamento_horas = 3
    deslocamento = timedelta(hours=deslocamento_horas)
    agora = datetime.now(timezone.utc)
    horario_local3 = agora.replace(hour=hora, minute=minuto, second=0, microsecond=0) + deslocamento
    return horario_local3
    
# Horario desejado no fuso horario -3 (exemplo: 14:25)
horario_fuso_horario_menos_3 = corrigirRelogio("00:01")
# Agendar a tarefa para o horario UTC
schedule.every().day.at(horario_fuso_horario_menos_3.strftime("%H:%M")).do(ajustarRelogioEqs)

print("...AGENDAMENTOS INICIADA...")

while True:
    schedule.run_pending()
    if onFalha:
        print("❌ Falha ao conectar em algum equipamento. Listando os equipamentos.")
        listaMacEqs()
        onFalha = False
    time.sleep(60)