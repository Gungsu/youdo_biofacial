from fastapi import FastAPI, Request, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.concurrency import run_in_threadpool
from contextlib import asynccontextmanager
from pydantic import BaseModel
from pythonping import ping
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from typing import Optional, List, Union
from datetime import datetime
import asyncio
import json
import uvicorn, logging
import ydAPI1 as yd
import nmap, netifaces, ipaddress
import re, time
import subprocess
import requests as RQfunction
import sys
import vpnactions as vpn
from pathlib import Path
from colorama import Fore, Style, init
from datetime import datetime, timezone

#from bdTiny import bdT, client, equipament
#import time
#import os.path
#import logging
#import asyncio

#necessidade de colocar alteração ou adicão de acesso aos equipamentos
#necessidade de colocar alteração nos equipamentos retirar acesso web

logging.basicConfig(
    level=logging.INFO,
    format="          %(asctime)s",
    datefmt="%d-%m-%Y %H:%M:%S",
)

COR_VERDE = '\033[92m'
RESET_COR = '\033[0m'

lastUpdate = sys.version

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(Path(BASE_DIR, 'templates')))

softwareVersion = "2.1.0"
interfaceRede = "eth0"  # Defina a interface de rede padrão aqui
interfaceVPN = "wg0" # Defina a interface de rede da VPN aqui

WIREGUARD_CONF_PATH = Path('/etc/wireguard/wg0.conf')

#MongoDB connection details
MONGO_HOST = '192.168.101.1'

MONGO_PORT = 27017
DATABASE_NAME = 'biofacial'
LOGCOLLECTION_NAME = 'logsCent_2_1'
COLLECTION_EQ_NAME = 'equipamentos_2_1'

MEUIPVPN = "200.200.200.200" # Atualiza quando inicia
PORT = 557
MEUMAC = "00:00:00:00:00:00"
MEUIPLOCAL = "200.200.200.200"
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Código executado na inicialização da API
    # Verificando minhas configurações de rede
    global MEUIPVPN, MEUIPLOCAL, MEUMAC
    
    local_ip = await asyncio.to_thread(find_vpn_info_by_ip_range, MONGO_HOST+"/24")
    print("INFO: Verificando configurações de rede...")
    MEUIPVPN = local_ip['ip']
    
    local_info = await asyncio.to_thread(get_network_info, interfaceRede) 
    if local_info:
        MEUIPLOCAL = local_info.get('ip', MEUIPLOCAL) # Usa o valor antigo como fallback
        MEUMAC = local_info.get('mac', MEUMAC)
        #print(f"{COR_VERDE}INFO:{RESET_COR}     Rede Local: IP {MEUIPLOCAL}, MAC {MEUMAC}")
    
    print(f"{COR_VERDE}INFO:{RESET_COR}     Iniciando a aplicação e conectando ao MongoDB...")
    try:
        # Tenta conectar e armazena o cliente no estado da aplicação
        app.state.mongodb_client = MongoClient(
            MONGO_HOST,
            MONGO_PORT,
            serverSelectionTimeoutMS=5000,
            directConnection=True
        )
        # Verifica a conexão
        app.state.mongodb_client.admin.command('ping')
        print(f"{COR_VERDE}INFO:{RESET_COR}     Conexão com o MongoDB estabelecida com sucesso.")
        await bdLog("INFO","lifespan","Conexão com o MongoDB estabelecida com sucesso.")
        yield # A API fica em execução aqui
    finally:
        # Código executado no encerramento da API
        if hasattr(app.state, 'mongodb_client'):
            print(f"{COR_VERDE}INFO:{RESET_COR}     Fechando a conexão com o MongoDB...")
            app.state.mongodb_client.close()
            print(f"{COR_VERDE}INFO:{RESET_COR}     Conexão com o MongoDB fechada.")

# Registre o lifespan na sua instância do app
app = FastAPI(lifespan=lifespan)
app.mount("/imgs", StaticFiles(directory=str(Path(BASE_DIR, 'imgs'))), name="imgs")

################ FUNCÕES AUXILIARES ######################
# --- Função Principal para Verificar IPs de Equipamentos ---
def find_vpn_info_by_ip_range(vpn_network_cidr: str = None) -> Optional[dict]:
    """
    Método mais preciso: itera todas as interfaces e verifica se alguma
    possui um IP que pertence à rede da VPN especificada.
    """
    if not vpn_network_cidr:
        vpn_network_cidr = MONGO_HOST+"/24"  # Exemplo padrão, ajuste conforme necessário
        
    #print(f"\nINFO: Procurando por um IP no range da VPN: {vpn_network_cidr}")
    try:
        vpn_network = ipaddress.ip_network(vpn_network_cidr, strict=False)
        
        for interface in netifaces.interfaces():
            # A função get_network_info já lida com interfaces sem IP, etc.
            info = get_network_info(interface)
            
            if info and info.get('ip'):
                try:
                    ip_obj = ipaddress.ip_address(info['ip'])
                    # A mágica acontece aqui: verifica se o IP pertence à sub-rede
                    if ip_obj in vpn_network:
                        #print(f"✅ SUCESSO: IP {info['ip']} na interface '{interface}' pertence à rede da VPN.")
                        return info
                except ValueError:
                    # O IP retornado não era válido, continua para o próximo
                    continue
                    
        print(f"INFO: Nenhuma interface encontrada com um IP no range {vpn_network_cidr}.")
        return None
    except Exception as e:
        print(f"ERRO: Falha ao procurar por IP no range da VPN: {e}")
        return None


def get_network_info(interface_name: str = None) -> Optional[dict]:
    """
    Obtém IP, Máscara, MAC e CIDR de uma interface de rede.
    Se nenhuma interface for especificada, busca a interface do gateway padrão.
    """
    try:
        # Se nenhum nome de interface foi fornecido, encontra a padrão.
        if interface_name is None:
            gateways = netifaces.gateways()
            # Pega a interface do gateway padrão para IPv4
            default_gateway_info = gateways.get('default', {}).get(netifaces.AF_INET)
            
            if not default_gateway_info:
                print("ERRO: Nenhuma interface de gateway padrão encontrada.")
                return None
            
            # O nome da interface é o segundo item da tupla (ex: ('192.168.1.1', 'eth0'))
            interface_name = default_gateway_info[1]
            #print(f"INFO: Nenhuma interface especificada. Usando a padrão: '{interface_name}'")

        # O resto do seu código, agora operando em um nome de interface confiável
        addrs = netifaces.ifaddresses(interface_name)
        
        ipv4_info = addrs.get(netifaces.AF_INET, [{}])[0]
        link_info = addrs.get(netifaces.AF_LINK, [{}])[0]
        
        ip = ipv4_info.get('addr')
        netmask = ipv4_info.get('netmask')
        mac = link_info.get('addr')

        if not ip or not netmask:
            print(f"AVISO: A interface '{interface_name}' não possui um endereço IPv4 configurado.")
            return None

        # Calcula o prefixo CIDR a partir da máscara
        prefix_len = ipaddress.ip_network(f'0.0.0.0/{netmask}', strict=False).prefixlen
        
        return {
            "ip": ip,
            "netmask": netmask,
            "mac": mac,
            "cidr": f"{ip}/{prefix_len}"
        }
    except ValueError as e:
        print(f"ERRO: A interface '{interface_name}' não existe ou é inválida. Detalhes: {e}")
        return None
    except Exception as e:
        print(f"ERRO: Ocorreu um erro inesperado: {e}")
        return None

def listaIpEqs():
    #subnet = mIp.ipemask()
    #loop = asyncio.get_event_loop()
    makeSubnet = get_network_info()
    subnet = makeSubnet['ip']+"/24"
    #print(f"INFO: Subnet para varredura: {subnet}")
    #print(subnet[0])
    scanner = nmap.PortScanner()
    scanner.scan(subnet, arguments='-sP')
    #scanner.scan("192.168.0.0/24", arguments='-sP')
    listipeqsinlocal = []
    
    for host in scanner.all_hosts():
        #print(scanner[host]['vendor'])
        x = scanner[host]['vendor']
        key = list(iter(x))
        try:
            val = x.get(key[0])
            if val == 'Control iD':
                listipeqsinlocal.append(host)
        except:
            pass
    return listipeqsinlocal
    
def respPadrao(model,lista):
    resp = {"task": model}
    if model == "ERROR":
        resp["ERROR"] = lista
    elif "SUCCESS":
        resp["resp"] = lista
    elif "PARSE":
        resp["PARSE"] = lista
    return resp

async def bdLog(strType = "0",strFrom = "API_Local_2_1",strMsg = None):
    client = app.state.mongodb_client
    db = client[DATABASE_NAME]
    collection = db[LOGCOLLECTION_NAME]
    try:
        log_entry = {
            "type": strType,
            "json": strMsg,
            "from": MEUIPVPN,
            "timestamp": datetime.now(timezone.utc)
        }
        resp = collection.insert_one(log_entry)
    except Exception as e:
        print(f"ERRO: Falha ao registrar log no MongoDB: {e}")
    
########################## ENDPOINTS #############################

@app.get("/status")
async def status(request: Request):
    """
    Endpoint para verificar o status da API.
    Atualiza os dados da central no MongoDB.

    Retorna:
        dict: Um dicionário com a chave 'status' e o valor 'API is running'.
    """
    global MEUIPVPN, MEUIPLOCAL, MEUMAC
    print (f"INFO: IP VPN: {MEUIPVPN}, Rede Local: IP {MEUIPLOCAL}, MAC {MEUMAC}")
    print(f"INFO: Endpoint /status acessado.")
    
    client = None
    try:
        client = request.app.state.mongodb_client
        if not client:
            await bdLog("ERROR","statusequipamentos","Falha ao conectar ao MongoDB.")
            return json.dumps({"error": "Falha ao conectar ao MongoDB."})
        else:
            db = client[DATABASE_NAME]
            centrais_collection = db["centrais_2_1"]
            query = {"ip_VPN": {"$regex": MEUIPVPN}}
            update_data = {
                "$set": {
                    "ip_local": MEUIPLOCAL+":"+str(PORT),
                    "mac": MEUMAC,
                    "updatedAt": datetime.now(timezone.utc)
                }
            }
            result = centrais_collection.update_one(query, update_data, upsert=False)
            if result.matched_count > 0:
                if result.modified_count > 0:
                    #print("INFO: /status - Dados da central atualizados no MongoDB.")
                    await bdLog("INFO","status","Dados da central atualizados no MongoDB.")
                    db_update_status = "success_modified"
                else:
                    #print("INFO: /status - Dados da central já estavam atualizados no MongoDB.")
                    db_update_status = "success_not_modified"
            else:
                #print(f"WARN: /status - Nenhuma central encontrada com ip_VPN: {MEUIPVPN}. Nenhum dado foi atualizado.")
                await bdLog("WARN","status",f"Nenhuma central encontrada com ip_VPN: {MEUIPVPN}.")
                db_update_status = "failed_not_found"
        
    except Exception as e:
        print(f"ERROR: /status - Falha ao atualizar dados da central no MongoDB: {e}")
        await bdLog("ERROR","status",f"Falha ao atualizar dados da central: {str(e)}")
        db_update_status = f"failed_exception: {str(e)}"
    
    await bdLog("STATUS","status","API is running")
    return respPadrao("SUCCESS",{"status": "online", "db_update": db_update_status})

@app.get("/statusequipamentos")
async def statusequipamentos(request: Request):
    """
    Conecta ao MongoDB, encontra o device_id da central local,
    busca equipamentos associados e verifica o status online via ping.

    Retorna:
        str: Um JSON contendo uma lista dicionários com 'ip' e 'status' (online/offline).
    """
    client = None
    try:
        client = request.app.state.mongodb_client
        
        if not client:
            await bdLog("ERROR","statusequipamentos","Falha ao conectar ao MongoDB.")
            return json.dumps({"error": "Falha ao conectar ao MongoDB."})

        db = client[DATABASE_NAME]
        
        centrais_collection = db["centrais_2_1"]
        equipamentos_collection = db["equipamentos_2_1"]
        
        local_ip = get_network_info(interfaceRede)["ip"]  # Remove a máscara CIDR para obter apenas o IP //"192.168.0.216/24"
        
        query = {"ip_local": {"$regex": local_ip}}
        central_doc = centrais_collection.find_one(query)

        if not central_doc:
            print(f"Nenhuma central encontrada com o IP '{local_ip}' na coleção 'centrais/ip local'.")
            await bdLog("ERROR","statusequipamentos",f"Central com IP '{local_ip}' não encontrada 'centrais/ip local'.")
            return respPadrao("ERROR",{"error": f"Central com IP '{local_ip}' não encontrada 'centrais/ip local'."})

        myDevice_id = central_doc["device_id"]
        
        lista_de_ips = equipamentos_collection.distinct("ip", {"central_id": myDevice_id})
        
        # 4. Fazer ping em cada IP e coletar o status
        resultados_ping = []
        for ip in lista_de_ips:
            status = "offline"
            try:
                # O parâmetro count=1 envia apenas 1 pacote ICMP
                # O parâmetro timeout=1 define o timeout em segundos
                # O verbose=False suprime a saída detalhada do ping
                response = await run_in_threadpool(ping, ip, count=1, timeout=1, verbose=False)
                # Verifica se há pelo menos uma resposta bem-sucedida
                if any(r.success for r in response):
                    log = await run_in_threadpool(yd.payLogin, ip)
                    if log == 0:
                        status = "offline"
                    else:
                        status = "online"
                        await run_in_threadpool(yd.logout, ip)
            except Exception as e:
                # print(f"Erro ao pingar {ip}: {e}")
                status = "erro_ping" # Adiciona um status para erros no ping
            
            resultados_ping.append({"ip": ip, "status": status})
            # print(f"Ping para {ip}: {status}")

        # 5. Retornar o status em JSON
        #return json.dumps(resultados_ping, indent=4) # indent=4 para formatação legível
        await bdLog("STATUS",request.client,resultados_ping)
        return respPadrao("SUCCESS",resultados_ping) # indent=4 para formatação legível

    except Exception as e:
        print(f"Ocorreu um erro geral: {e}")
        await bdLog("ERROR",request.client,f"Erro interno: {str(e)}")
        return respPadrao("ERROR",{"error": f"Erro interno: {str(e)}"})

@app.get("/infaceList")
async def list_active_network_interfaces() -> List[str]:
    """
    Lista os nomes das interfaces de rede ativas no sistema.

    Retorna:
        List[str]: Uma lista de strings, onde cada string é o nome de uma interface ativa.
                   Retorna uma lista vazia em caso de erro ou se nenhuma interface ativa for encontrada.
    """
    active_interfaces = []
    try:
        # Executa o comando 'ip a'
        co = subprocess.Popen(['ip', 'a'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = co.communicate()

        if co.returncode != 0:
            print(f"Erro ao executar 'ip a': {error.decode('utf-8').strip()}")
            return []

        ip_output = output.decode("utf-8")

        # Expressão regular para encontrar nomes de interfaces
        # Uma interface ativa geralmente começa com um número e o nome da interface,
        # seguido por ': <FLAGS> UP'.
        # Ex: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"
        # ou "3: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP>"
        # O re.MULTILINE permite que '^' e '$' correspondam ao início/fim de cada linha
        # O re.IGNORECASE torna a busca case-insensitive
        
        # Padrão para encontrar o nome da interface e verificar se está "UP"
        # O primeiro grupo de captura (.*?) pega o nome da interface
        pattern = re.compile(r'^\d+:\s+(\w+):\s+<.*UP.*>', re.MULTILINE | re.IGNORECASE)
        
        matches = pattern.finditer(ip_output) # finditer retorna um iterador de objetos match

        for match in matches:
            interface_name = match.group(1) # O grupo 1 contém o nome da interface
            if interface_name not in ['lo']: # Opcional: Ignorar a interface de loopback
                active_interfaces.append(interface_name)
        
        await bdLog("INFO","infaceList",active_interfaces)
        return active_interfaces

    except FileNotFoundError:
        print("Erro: O comando 'ip' não foi encontrado. Certifique-se de que está instalado e no PATH.")
        return []
    except Exception as e:
        print(f"Ocorreu um erro inesperado ao listar interfaces de rede: {e}")
        return []

@app.get("/index", response_class=HTMLResponse)
async def create_index(request: Request):
    context = {'request': request, 'lastUpdate': lastUpdate}
    await bdLog("INFO","index","Acessou pagina index")
    return templates.TemplateResponse("index.html", context)

@app.get("/findEqs")
async def procurar_eqs(req: str = "vazio"):
    print("INFO: Commando feqs recebido")
    #LISTAR IP DE EQS REGISTRADOS
    #PEGAR NO BD
    nlist = []
    nlist3 = []

    #LISTAR IPS DE EQS NA REDE
    nlist2 = listaIpEqs()
    nlist2 = list(set(nlist2))
    
    #dif = [ip for ip in nlist2 if ip not in nlist]
    client = app.state.mongodb_client
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_EQ_NAME]
    
    for eq in nlist2:
        r = yd.payLogin(eq)
        if r == 0:
            print(f"INFO: Equipamento {eq} offline")
            continue
        if r == 2:
            print(f"INFO: Equipamento {eq} confIniciais realizadas.")
            await bdLog("INFO","findEqs",f"Equipamento {eq} confIniciais realizadas.")
            nlist.append({"ip": eq, "status": "conf de rede realizadas"})
            r = yd.payLogin(eq)
        
        response = yd.eqInfo(eq)
        if response == 0:
            print(f"INFO: Equipamento {eq} offline")
            continue
        
        mac = response["network"]["mac"]
        ip = response["network"]["ip"]
        name = response["network"]["device_hostname"]
        device_id = response["device_id"]
        filter_query = {"mac": mac}
        jsno = {
            "mac": mac,
            "ip": ip,
            "name": name,
            "device_id": device_id
        }
        jsno2 = {"$set": {
            "mac": mac,
            "ip": ip,
            "device_hostname": name,
            "device_id": device_id,
            "updatedAt": datetime.now(timezone.utc)
        } }
        nlist.append(jsno)
        resultado = collection.update_one(filter_query, jsno2, upsert=False)
        
        if resultado.modified_count == 0:
            nlist3.append(jsno)
            
        yd.logout(eq)
    
    for n in nlist3:
        value = Equipament(ip=n["ip"])
        await eqInitConfs(value)
        
    resp = {"ListadeEqs": nlist}
    await bdLog("GET","findEqs",req)
    return respPadrao("SUCCESS",resp)
class clientList(BaseModel):
    idYD: Optional[list] = None
    base64: Optional[list] = None
    userList: Optional[list] = None
    acesso: Optional[str] = None

class Client(BaseModel):
    name: Optional[str] = None
    idYD: Optional[str] = None
    password: Optional[str] = None
    begin_time: Optional[str] = None
    end_time: Optional[str] = None
    acessos: Optional[list] = None
    base64: Optional[str] = None
    admin: Optional[int] = None
    
class Equipament(BaseModel):
    _id: Optional[str] = None
    id: Optional[str] = None
    device_hostname: Optional[str] = None
    ip: Optional[str] = None
    mac: Optional[str] = None
    device_id: Optional[str] = None
    ## Usado apenas para enviar log de entrada para o endPoint
    last_userLog: Optional[str] = None
    ipFs: Optional[str] = None
    nipVPN: Optional[str] = None

@app.post("/cadListClientes")
async def cadListClientes(soli: clientList):
    cadastrodecliente = soli
    listaParaCadastro = []
    listaParaCadastroImg = []
    listaParaCadastroGroup = []
    agora_utc = datetime.now(timezone.utc)
    timestamp = agora_utc.timestamp()
    timeStamp = int(timestamp) - 10800
    for ids in cadastrodecliente.userList:
        date_btstmp = datetime.strptime(ids['acessos'][0]['begin_time'], "%d-%m-%Y %H:%M:%S")
        date_etstmp = datetime.strptime(ids['acessos'][0]['end_time'], "%d-%m-%Y %H:%M:%S")
        begin_time_timestamp = int(date_btstmp.timestamp()) - 10800
        end_time_timestamp = int(date_etstmp.timestamp()) - 10800
        tmpDict = {
            "id": yd.converter_para_int(ids['idYD']),
            "name": ids['name'],
            "registration": ids['idYD'],
            "password": "589713",
            "begin_time": begin_time_timestamp,
            "end_time": end_time_timestamp
        }
        tmpDict2 = {
            "user_id": yd.converter_para_int(ids['idYD']),
            "image": ids['base64'],
            "timestamp": timeStamp
        }
        tmpDict3 = {
            "user_id": yd.converter_para_int(ids['idYD']),
            "group_id": 1
        }
        listaParaCadastro.append(tmpDict)
        listaParaCadastroImg.append(tmpDict2)
        listaParaCadastroGroup.append(tmpDict3)
    try:
        yd.payLogin(cadastrodecliente.acesso)
        yd.addListUser(cadastrodecliente.acesso,listaParaCadastro,listaParaCadastroGroup)
        yd.addListimageUpdt(cadastrodecliente.acesso,listaParaCadastroImg,timeStamp)
        yd.logout(cadastrodecliente.acesso)
    except:
        await bdLog("ERROR","cadListClientes","Equipamento offline ou erro ao cadastrar lista")
        return respPadrao("ERROR","Equipamento offline ou erro ao cadastrar lista")
    
    await bdLog("CAD_LIST_CLIENTE","cadListClientes","Espelhado")
    return respPadrao("SUCCESS","Lista de clientes cadastrada com sucesso")

@app.post("/cadastro_cl")
async def incluir_novo_cadastro_cl(soli: Client):
    cadastrodecliente = soli
    #se todos dispositivos validos realizando cadastros
    acessosDict = []
    errorsCont = 0
    successCont = 0
    arrayOff = []
    for portas in cadastrodecliente.acessos:
        if yd.payLogin(portas) == 0:
            errorDict = {"device_id": "0", "status": "0"}
            errorDict["device_id"] = portas
            errorDict["status"] = "offline"
            arrayOff.append(errorDict)
            errorsCont += 1
            continue
        
        else:
            ret = '{"ids": "00"}'
            jsonValues = yd.loadUsers(portas)
            clCad = False
            
            if jsonValues["users"] == []:
                ret = yd.addUser(portas,
                                 cadastrodecliente.name,
                                 cadastrodecliente.idYD,
                                 cadastrodecliente.password,
                                 cadastrodecliente.begin_time,
                                 cadastrodecliente.end_time)
                clCad = True
            else:
                for regs in jsonValues["users"]:
                    if regs["registration"] == cadastrodecliente.idYD:
                        errorDict = {"device_id": "0", "status": "0"}
                        errorDict["device_id"] = portas
                        errorDict["status"] = "cliente ja cadastrado"
                        arrayOff.append(errorDict)
                        errorsCont += 1
                        ret = '{"ids": ['+str(regs["id"])+']}'
                        clCad = True
            
            if not clCad:
                ret = yd.addUser(portas,
                                 cadastrodecliente.name,
                                 cadastrodecliente.idYD,
                                 cadastrodecliente.password,
                                 cadastrodecliente.begin_time,
                                 cadastrodecliente.end_time)
                successCont += 1

            if isinstance(ret, str):
                ret = json.loads(ret)
                acessosDict.append({"device_ip": portas, "user_idDevice": ret["ids"][0]})
            else:
                errorDict = {"device_id": "0", "status": "0"}
                errorDict["device_id"] = portas
                errorDict["status"] = str(ret)
                arrayOff.append(errorDict)
                errorsCont += 1
        yd.logout(portas)
    
    cadastrodecliente.acessos = acessosDict
    cadastrodecliente.base64 = "none"
    await bdLog("CAD_CLIENTE","cadastro_cl",soli.dict())
    if errorsCont >= 1 and successCont >= 1:
        return respPadrao("PARSE",{"ERROR": arrayOff, "SUCCESS": cadastrodecliente})
    elif successCont >= 1:
        return respPadrao("SUCCESS",cadastrodecliente)
    else:
        return respPadrao("ERROR",arrayOff)

@app.post('/cad_bio')
async def cadastrarBio(soli: Client):
    cada_bio = soli
    try:
        idYD = cada_bio.idYD
        b64img = cada_bio.base64
        acessos = cada_bio.acessos
    except:
        await bdLog("ERROR","cad_bio","Campo base64 ou acessos obrigatorio")
        return respPadrao("ERROR","Campo base64 e acessos obrigatorio")

    contOff = 0
    arrayOff = []
    respRet = []
    resp = []
    retCads = False
    for porta in soli.acessos:
        vl = yd.payLogin(porta)
        if vl == 0:
            tmpVar = {"device_ip": porta, "status": "Offline"}
            arrayOff.append(tmpVar)
            contOff += 1
        else:
            bdUsers = yd.loadUsers(porta)
            userIdinPorta = -1
            resp = {"success": False, "error": "nada"}
            for user in bdUsers["users"]:
                if user["registration"] == cada_bio.idYD:
                    userIdinPorta = user["id"]
                    break

            c = datetime.now()
            current_time = c.strftime('%d-%m-%Y %H:%M:%S')
            
            if userIdinPorta == -1:
                tmpVar = {"device_ip": porta, "ERROR": "UserID nao encontrado"}
                arrayOff.append(tmpVar)
                contOff += 1
            else:
                current_time = c.strftime('%d-%m-%Y %H:%M:%S')
                resp = yd.imageUpdt(porta,userIdinPorta,b64img,current_time)
                try:
                    if 'success' in resp and resp['success'] is True:
                        pass
                    else:
                        tmpVar = {"device_ip": porta, "ERROR": "base64 nao reconhecida"}
                        yd.delUser(porta,userIdinPorta)
                        arrayOff.append(tmpVar)
                        contOff += 1
                except:
                    tmpVar = {"device_ip": porta, "ERROR": "base64 nao reconhecida"}
                    yd.delUser(porta,userIdinPorta)
                    arrayOff.append(tmpVar)
                    contOff += 1
                    pass
                yd.logout(porta)
            
            try:
                if resp["success"] == True and contOff == 0:
                    retCads = True
                    resp = {"device_id": porta, "success": True}
                    respRet.append(resp)
                else:
                    if retCads == False:
                        resp = {"device_id": porta, "success": False}
                        respRet.append(resp)
            except:
                pass
    await bdLog("CAD_BIO","cad_bio",cada_bio.dict())
    if contOff>=1:
        return respPadrao("ERROR",arrayOff)
    else:
        return respPadrao("SUCCESS",respRet)

@app.get("/central")
async def central(request: Request):
    try:
        soliInterface = request.query_params.get("interface", interfaceRede)
    except:
        soliInterface = interfaceVPN
    
    #print(f"INFO: Interface solicitada: {soliInterface}")
    dadosNetwork = get_network_info()
    myMac = dadosNetwork["mac"]
    myIp = dadosNetwork["ip"]
    myVersion = softwareVersion
    dadosNetworkVPN = get_network_info(interfaceVPN)
    myIPVPN = dadosNetworkVPN["ip"]+":"+str(PORT)
    resp = {"mac": myMac, "ip_local": myIp, "ip_vpn": myIPVPN, "version": myVersion}
    value = request
    await bdLog("GET","central","Acessou dados da central")
    return respPadrao("SUCCESS", resp)

@app.get("/clientes_eq")
async def clientes_eq(ip: str):
    vl = yd.payLogin(ip)
    if vl == 0:
        errorDict = {"device_ip": "0", "status": "0"}
        errorDict["device_ip"] = ip
        errorDict["status"] = "offline"
        await bdLog("ERROR","clientes_eq",ip)
        return respPadrao("ERROR",errorDict)
    else:
        response = yd.loadUsers(ip)
        #json_conv = json.loads(response)
        resp = response['users']
        yd.logout(ip)
        await bdLog("ERROR","clientes_eq",ip)
        return respPadrao("SUCCESS",resp)
    
@app.put('/cadastro_eq')
async def udate_eq(soli: Equipament):
    updateEQ = soli
    try:
        ip = updateEQ.ip
        device_hostname = updateEQ.device_hostname
    except:
        await bdLog("ERROR","cadastro_eq",soli.dict())
        return respPadrao("ERROR","Falta de parametro id, ip ou device_hostname")

    if yd.payLogin(ip) == 0:
        await bdLog("ERROR","cadastro_eq",soli.dict())
        return respPadrao("ERROR","Equipamento nao encontrado")

    novo_cadastro = {}
    yd.updateDevice(soli.ip,device_hostname)
    
    r = yd.payLogin(soli.ip)
    if r == 0:
        print(f"INFO: Equipamento {soli.ip} offline")
        await bdLog("ERROR","cadastro_eq",soli)
        return respPadrao("ERROR","Equipamento nao encontrado depois de atualizar")
    ret = yd.eqInfo(soli.ip)
    yd.logout(soli.ip)
    
    novo_cadastro["ip"] = soli.ip
    novo_cadastro["mac"] = ret["network"]["mac"]
    novo_cadastro["device_hostname"] = ret["network"]["device_hostname"]
    novo_cadastro["device_id"] = ret["device_id"]

    await bdLog("PUT","cadastro_eq",soli)
    return respPadrao("SUCCESS",novo_cadastro)

@app.put("/fabricReset")
async def resetEquipament(soli: Equipament):
    try:
        ip_loc = soli.ip
    except:
        await bdLog("ERROR","fabricReset",soli)
        return respPadrao("ERROR", "Falta de parametro ip")
    resp = {}
    vl = yd.payLogin(ip_loc)
    if vl == 0:
        await bdLog("ERROR","fabricReset",soli)
        return respPadrao("ERROR","Equipamento nao encontrado")
    ### Resetar o equipamento ####
    yd.fabricReset(soli.ip)
    await bdLog("PUT","fabricReset",soli.dict())
    return respPadrao("SUCCESS", resp)

@app.put("/restartDevice")
async def restartEquipament(soli: Equipament):
    try:
        ip_loc = soli.ip
    except:
        await bdLog("ERROR","restartDevice",soli)
        return respPadrao("ERROR", "Falta de parametro ip")
    resp = {}
    vl = yd.payLogin(ip_loc)
    if vl == 0:
        await bdLog("ERROR","restartDevice",soli)
        return respPadrao("ERROR","Equipamento nao encontrado")
    ### Resetar o equipamento ####
    yd.restartDevice(soli.ip)
    await bdLog("PUT","restartDevice",soli.dict())
    return respPadrao("SUCCESS", resp)

@app.put("/eqInitConfs")
async def eqInitConfs(soli: Equipament):
    try:
        ip_loc = soli.ip
    except:
        await bdLog("ERROR","eqInitConfs",soli)
        return respPadrao("ERROR", "Falta de parametro ip")
    resp = {}
    vl = yd.payLogin(ip_loc)
    if vl == 0:
        await bdLog("ERROR","eqInitConfs",soli)
        return respPadrao("ERROR","Equipamento nao encontrado")
    ### Realizar configurações iniciciais ####
    ### ADD User for adm ###
    userFadm = yd.addUser(soli.ip,"Administrador","1","1313","13-03-2024 11:00:00","13-03-2028 11:00:00")
    if userFadm == -1:
        await bdLog("ERROR","eqInitConfs","ja existe conf inciais")
        return respPadrao("ERROR","Nao foi possivel criar o usuario Administrador")
    userFadm = json.loads(userFadm)
    ### ADD Admin   ###
    res = yd.adduserAdm(soli.ip,userFadm["ids"][0],1)
    ### ativar envio de logs para central ####
    #yd.activeLogs(soli.ip,allIps()[0])
    ### Setar hora conforme servidor ####
    yd.setTime(soli.ip)
    ### ADD Logo    ###
    yd.addLogo(soli.ip)
    ### ADD Sounds  ###
    # yd.soundCustom(soli.ip)
    # yd.addSoundMessage(soli.ip)
    ### Active Door Sensor  ###
    yd.activeSensor(soli.ip,"1","5")
    #yd.setwebaccess(soli.ip,"0")
    yd.logout(ip_loc)
    await bdLog("PUT","eqInitConfs",soli.dict())
    return respPadrao("SUCCESS", resp)

@app.put('/atualiza_cl')
async def update_cad(soli: Client):
    updateCl = soli
    arrayOff = []
    aceList = []
    errorsCont = 0
    #testando Json.
    try:
        idYD = updateCl.idYD
        acess = updateCl.acessos
        if idYD == None:
            await bdLog("ERROR","atualiza_cl","Campo idYD e acessos obrigatorio")
            return respPadrao("ERROR","Campo idYD e acessos obrigatorio")
    except:
        await bdLog("ERROR","atualiza_cl","Campo idYD obrigatorio")
        return respPadrao("ERROR","Campo idYD obrigatorio")
    
    nameCl = updateCl.name
    passw = updateCl.password or None
    bTime = updateCl.begin_time or None
    eTime = updateCl.end_time or None
    base64 = updateCl.base64
    
    acess.sort()
    
    boolAtualizarBD = False
    listaAcessos = []
        
    #procurando pelo id em cada acesso para atualizar
    for porta in acess:
        vl = yd.payLogin(porta)
        if vl == 0:
            errorDict = {"device_ip": "0", "status": "0"}
            errorDict["device_ip"] = porta
            errorDict["status"] = "offline"
            arrayOff.append(errorDict)
            errorsCont += 1
        else:
            bdUsers = yd.loadUsers(porta)
            userActve = [u for u in bdUsers["users"] if u['registration'] == idYD]
            c = datetime.now()
            current_time = c.strftime('%d-%m-%Y %H:%M:%S')
            #Em caso de cadastro nao existir no equipamento
            if userActve == []:
                #BUSCAR NO BD
                return respPadrao("ERROR","Cliente nao encontrado no equipamento, favor usar o endpoint de cadastro")
                client = app.state.mongodb_client
                db = client[DATABASE_NAME]
                collection = db["usuarios_2_1"]
                
                user_data = collection.find_one({"idYD": idYD})
                if user_data:
                    nameCl = user_data["name"]
                    passw = user_data["password"]
                    if bTime == None or bTime == "" or bTime == "none":
                        bTime = user_data["acessos"][0]["begin_time"]
                    if eTime == None or eTime == "" or eTime == "none":
                        eTime = user_data["acessos"][0]["end_time"]
                    base64 = user_data["base64"]
                    
                yd.addUser(porta,nameCl,idYD,passw,bTime,eTime)
                boolAtualizarBD = True
                listaAcessos.append(porta)
                bdUsers = yd.loadUsers(porta)
                userActve = [u for u in bdUsers["users"] if u['registration'] == idYD]
                if base64 != "none" and base64 != None:
                    resp2 = yd.imageUpdt(porta,userActve[0]["id"],base64,current_time)
            else:
                if nameCl == None or nameCl == "" or nameCl == "none":
                    nameCl = userActve[0]["name"]
                if passw == None or passw == "" or passw == "none":
                    passw = userActve[0]["password"]
                if bTime == None or bTime == "" or bTime == "none":
                    bTime = userActve[0]["begin_time"]
                if eTime == None or eTime == "" or eTime == "none":
                    eTime = userActve[0]["end_time"]
                yd.updateUser(porta,userActve[0]["id"],nameCl,idYD,passw,bTime,eTime)
                if base64 != "none" and base64 != None:
                    resp2 = yd.imageUpdt(porta,userActve[0]["id"],base64,current_time)
                    try:
                        if 'success' in resp2 and resp2['success'] is True:
                            pass
                        else:
                            tmpVar = {"device_ip": porta, "ERROR": "base64 nao reconhecida"}
                            arrayOff.append(tmpVar)
                            errorsCont += 1
                    except:
                        tmpVar = {"device_ip": porta, "ERROR": "base64 nao reconhecida"}
                        arrayOff.append(tmpVar)
                        errorsCont += 1
                        pass

            aceList.append({
                "device_ip": porta,
                "user_idDevice": userActve[0]["id"]
            })
            
            yd.logout(porta)
    
    if boolAtualizarBD:
        client = app.state.mongodb_client
        db = client[DATABASE_NAME]
        collection = db["usuarios_2_1"]
        
        collection.update_one({"idYD": idYD}, {"$set": {"name": nameCl, "password": passw, "acessos": [{"begin_time": bTime, "end_time": eTime}]}})
    
    if errorsCont>=1:
        await bdLog("ERROR","atualiza_cl",soli.dict())
        return respPadrao("ERROR",arrayOff)
    else:
        await bdLog("PUT","atualiza_cl",soli.dict())
        return respPadrao("SUCCESS",aceList)

@app.delete('/del_cl_2_1')
async def del_cadastro_cl(soli: Client):
    cadastrodecliente = soli
    try:
        idYD = cadastrodecliente.idYD
        if idYD == None:
            await bdLog("ERROR","del_cl_2_1","Campo idYD e acessos obrigatorio")
            return respPadrao("ERROR","Campo idYD e acessos obrigatorio")
    except:
        await bdLog("ERROR","del_cl_2_1","Campo idYD obrigatorio")
        return respPadrao("ERROR","Campo idYD obrigatorio")
    arrayOff = []
    errorsCont = 0
    successCont = 0
    userNencontrado = 0
    
    for porta in cadastrodecliente.acessos:
        ip = porta
        vl = yd.payLogin(ip)
        if vl == 1:
            bdUsers = yd.loadUsers(ip)
            #print(bdUsers)
            #return respPadrao("SUCCESS",bdUsers)
            userActve = [u for u in bdUsers["users"] if u['registration'] == cadastrodecliente.idYD]

            #Em caso de cadastro nao existir no equipamento
            if userActve == []:
                myResp = {"code": "ERROR", "desc": "Cliente nao cadastrado no acesso"}
                myResp["device_ip"] = porta
                userNencontrado += 1
            else:
                successCont += 1
                success = {"code": "SUCCESS", "desc": "Cliente deletado com sucesso"}
                for us in userActve:
                    yd.delUser(ip,us["id"])
            
            yd.logout(ip)
        else:
            errorDict = {"device_ip": "0", "status": "0"}
            errorDict["device_ip"] = porta
            errorDict["status"] = "offline"
            arrayOff.append(errorDict)
            errorsCont += 1

    if errorsCont>=1 and userNencontrado>=1 and successCont>=1:
        resp = [{}]
        resp.append(myResp)
        resp.append(arrayOff)
        resp.append(success)
        await bdLog("PARSE","del_cl_2_1",soli.dict())
        return respPadrao("PARSE",resp)
    elif errorsCont>=1 and userNencontrado>=1 and successCont==0:
        resp = [{}]
        resp.append(myResp)
        resp.append(arrayOff)
        await bdLog("ERROR","del_cl_2_1",soli.dict())
        return respPadrao("ERROR",resp)
    elif successCont>=1:
        resp = [{}]
        resp.append(success)
        await bdLog("SUCCESS","del_cl_2_1",soli.dict())
        return respPadrao("SUCCESS",resp)
    elif userNencontrado>=1:
        resp = [{}]
        resp.append(myResp)
        await bdLog("ERROR","del_cl_2_1",soli.dict())
        return respPadrao("ERROR",resp)
    
@app.post("/update_vpn_ip")
async def update_vpn_ip(request: Request, soli: Equipament):
    """
    Endpoint para:
    1. Gerar um novo par de chaves WireGuard localmente.
    2. Enviar a nova chave pública e o IP desejado para o servidor VPN registrar.
    """
    novo_ip_VPN = soli.nipVPN
    SERVER_API_URL = "http://177.71.174.32:10610/add_vpn_client"
    # --- 1. Validação de Entrada ---
    if not novo_ip_VPN:
        await bdLog("ERROR", "update_vpn_ip", "O campo 'nipVPN' (novo IP) é obrigatório.")
        return respPadrao("ERROR", "O campo 'nipVPN' (novo IP) é obrigatório.")
    
    await bdLog("INFO", "update_vpn_ip", f"Iniciando atualização do IP da VPN para: {novo_ip_VPN}")

    # --- 2. Gerar Chaves Localmente ---
    # (Rodamos 'vpn.generate_wireguard_keys' em uma thread, 
    # pois é uma operação síncrona que usa subprocess)
    try:
        private_key, public_key = await asyncio.to_thread(vpn.generate_wireguard_keys, novo_ip_VPN)
        
        if not public_key:
            await bdLog("ERROR", "update_vpn_ip", "Falha ao gerar chaves WireGuard (função retornou None).")
            return respPadrao("ERROR", "Falha ao gerar chaves WireGuard localmente.")
    
    except Exception as e:
        # Isso pode acontecer se o 'wg' (WireGuard Tools) não estiver instalado
        await bdLog("ERROR", "update_vpn_ip", f"Exceção ao gerar chaves: {e}")
        return respPadrao("ERROR", f"Exceção ao gerar chaves: {str(e)}")

    # --- 3. Enviar Chave para o Servidor ---
    payload = {
        "ip_vpn": novo_ip_VPN,
        "public_key": public_key
    }
    
    # (Usamos uma função wrapper para rodar o 'requests' síncrono em uma thread)
    def request_to_server():
        try:
            # Usando o alias 'RQfunction' que você tem no seu APILocal_2_1.py
            response = RQfunction.post(SERVER_API_URL, json=payload, timeout=15)
            response.raise_for_status() # Lança um erro se o status for 4xx ou 5xx
            return response.json()
        except Exception as e:
            # Captura exceções (ConnectionError, HTTPError, etc.)
            return {"status": "exception", "message": str(e)}

    await bdLog("INFO", "update_vpn_ip", f"Enviando nova chave pública para o servidor: {SERVER_API_URL}")
    server_response = await asyncio.to_thread(request_to_server)

    # --- 4. Tratar Resposta do Servidor ---
    response_status = server_response.get("status")
    response_message = server_response.get("message", "Resposta inválida do servidor.")

    if response_status == "sucesso":
        await bdLog("SUCCESS", "update_vpn_ip", f"IP {novo_ip_VPN} registrado com sucesso no servidor.")
        return respPadrao("SUCCESS", server_response)
        
    elif response_status == "negado":
        await bdLog("WARN", "update_vpn_ip", f"Servidor negou o IP {novo_ip_VPN} (provavelmente já existe). Msg: {response_message}")
        return respPadrao("ERROR", response_message)
        
    elif response_status == "exception":
        await bdLog("ERROR", "update_vpn_ip", f"Falha ao contatar o servidor: {response_message}")
        return respPadrao("ERROR", f"Falha de comunicação com o servidor: {response_message}")

    else:
        await bdLog("ERROR", "update_vpn_ip", f"Resposta inesperada do servidor: {server_response}")
        return respPadrao("ERROR", f"Resposta inesperada do servidor: {server_response}")
    
if __name__ == '__main__':
    print("Software inicializado... - Listening")
    time.sleep(5)
    print('Iniciando o servidor na porta:', PORT)
    #uvicorn.run(app, host='0.0.0.0', port=PORT)
    uvicorn.run(
        "APILocal_2_1:app",
        host="0.0.0.0", # Escuta em todas as interfaces
        port=PORT,
        reload=True
    )