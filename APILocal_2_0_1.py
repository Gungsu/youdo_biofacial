from fastapi import FastAPI, Request, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pymongo import MongoClient
from typing import Optional
from datetime import datetime, timezone
from pathlib import Path
from bdTiny import bdT, client, equipament
from contextlib import asynccontextmanager
from pythonping import ping
import json
import uvicorn
import logging
import ydAPI1 as yd
import nmap
import requests as RQfunction
import sys
import netifaces
import ipaddress
# import time
# import socket
# import subprocess
# import asyncio
# import re
# import os.path

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(levelname)s: %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

programPoint = 0
#0 - TesteDebug
#1 - Production

class Client(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    idYD: Optional[str] = None
    debug: Optional[str] = None
    password: Optional[str] = None
    begin_time: Optional[str] = None
    end_time: Optional[str] = None
    acessos: Optional[list] = None
    bio: Optional[str] = None
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
    
class ComunGeneric(BaseModel):
    fromDev: Optional[str] = None
    toDev: Optional[str] = None
    idYD: Optional[str] = None
    debug: Optional[str] = None
    device_id: Optional[str] = None
    device_id: Optional[int] = None
    object_changes: Optional[dict] = None
    time: Optional[int] = None

retERRORjson = [
    {
        "code": "ERROR00",
        "desc": "Json Incompleto ou mal formatado"
    },
    {
        "code": "ERROR01",
        "desc": "ip equipamento ja cadastrado"
    },
    {
        "code": "ERROR02",
        "desc": "nao foi possivel conectar no eq."
    },
    {
        "code": "ERROR03",
        "desc": "idYD ja cadastrado."
    },
    {
        "code": "ERROR04",
        "desc": "idYD nao cadastrado."
    },
    {
        "code": "ERROR05",
        "desc": "nao foi possivel ler imagem."
    },
    {
        "code": "ERROR06",
        "desc": "nao ha imagem em base64."
    },
    {
        "code": "ERROR07",
        "desc": "Houve mudanca em dispositivos solicite nova lista."
    },
    {
        "code": "ERROR08",
        "desc": "Equipamento - offline."
    }
]

#last update in delcl function


if programPoint == 0:
    db_eq_f = Path(__file__).parent / 'dbEq.json'
    db_cl_f = Path(__file__).parent / 'dbCl.json'
else:
    db_eq_f = Path(__file__).parent / '/root/dbEq.json'
    db_cl_f = Path(__file__).parent / '/root/dbCl.json'
    
api_f = Path(__file__).parent / 'APILocal.py'
logFromEq = Path(__file__).parent / 'eqsLog.json'

db_cl = bdT(db_cl_f)
db_eq = bdT(db_eq_f)

COR_VERDE = '\033[92m'
RESET_COR = '\033[0m'

# MongoDB connection details
MONGO_HOST = '192.168.101.1'
MONGO_PORT = 27017
DATABASE_NAME = 'biofacial'
COLLECTION_NAME = 'usuarios' # Replace with your actual collection name
COLLECTION_CT_NAME = 'centrais_2_1'

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Código executado na inicialização da API
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
        
        await bdLog("INFO", "Lifespan-Startup", {"message": "API INICIADA E CONECTADA AO DB"})
        
        yield # A API fica em execução aqui
    finally:
        # Código executado no encerramento da API
        if hasattr(app.state, 'mongodb_client'):
            print(f"{COR_VERDE}INFO:{RESET_COR}     Fechando a conexão com o MongoDB...")
            app.state.mongodb_client.close()
            print(f"{COR_VERDE}INFO:{RESET_COR}     Conexão com o MongoDB fechada.")

# Registre o lifespan na sua instância do app
app = FastAPI(lifespan=lifespan)

async def bdLog(strType = "0",strFrom = "API_Local_2_0_1",strMsg = None):
    LOGCOLLECTION_NAME = 'logsCent_2_0_1'
    client = app.state.mongodb_client
    db = client[DATABASE_NAME]
    collection = db[LOGCOLLECTION_NAME]
    myip = myData()["ip_vpn"]
    try:
        log_entry = {
            "type": strType,
            "json": strMsg,
            "from": strFrom,
            "central": myip,
            "timestamp": datetime.now(timezone.utc)
        }
        collection.insert_one(log_entry)
    except Exception as e:
        print(f"ERRO: Falha ao registrar log no MongoDB: {e}")
    

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

def myData():
    # Função que mantem atualizada o servidor quanto a "meu" ip local
    dataResp = {"ip_local": "", "ip_vpn": "", "device_id": "", "mac": "", "netMask": ""}
    
    dadosLocais = get_network_info()
    dadosVPN = get_network_info("wg-client")
    
    client = app.state.mongodb_client
    if not client:
        print("ERRO: Falha ao conectar ao MongoDB.")
        return dataResp
    
    db = client[DATABASE_NAME]
        
    centrais_collection = db["centrais_2_1"]
    
    query = {"ip_VPN": {"$regex": dadosVPN["ip"]}}
    central_doc = centrais_collection.find_one(query)
    
    if central_doc:
        myDevice_id = central_doc["device_id"]
        
    if central_doc["ip_local"] != dadosLocais["ip"]:
        horario_atual_utc = datetime.now(timezone.utc)
        centrais_collection.update_one({"device_id": myDevice_id}, {"$set": {"ip_local": dadosLocais["cidr"],
                                                                             "updatedAt": horario_atual_utc}})
    
    dataResp = {
        "ip_local": dadosLocais["ip"],
        "ip_vpn": dadosVPN["ip"],
        "device_id": myDevice_id,
        "mac": dadosLocais["mac"],
        "netMask": dadosLocais["netmask"]
    }
    
    return dataResp

@app.get("/statusequipamentos")
async def statusequipamentos(request: Request):
    """
    Conecta ao MongoDB, encontra o device_id da central local,
    busca equipamentos associados e verifica o status online via ping.

    Retorna:
        str: Um JSON contendo uma lista de dicionários com 'ip' e 'status' (online/offline).
    """
    client = None
    try:
        client = request.app.state.mongodb_client
        
        if not client:
            return json.dumps({"error": "Falha ao conectar ao MongoDB."})

        db = client[DATABASE_NAME]
        
        centrais_collection = db["centrais_2_1"]
        equipamentos_collection = db["equipamentos_2_1"]
        
        local_ip = get_network_info()["ip"]
        
        query = {"ip_local": {"$regex": local_ip}}
        central_doc = centrais_collection.find_one(query)

        if not central_doc:
            print(f"Nenhuma central encontrada com o IP '{local_ip}' na coleção 'centrais/ip local'.")
            print("Atualizando dados locais...")
            myData()
            return respPadrao("ERROR",{"incompleta": f"Central com IP '{local_ip}' dados atualizados."})

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
                response = ping(ip, count=1, timeout=1, verbose=False)
                # Verifica se há pelo menos uma resposta bem-sucedida
                if any(r.success for r in response):
                    log = yd.payLogin(ip)
                    if log == 0:
                        status = "offline"
                    else:
                        status = "online"
                        yd.logout(ip)
            except Exception as e:
                # print(f"Erro ao pingar {ip}: {e}")
                status = "erro_ping" # Adiciona um status para erros no ping
            
            resultados_ping.append({"ip": ip, "status": status})
            # print(f"Ping para {ip}: {status}")

        # 5. Retornar o status em JSON
        await bdLog("statusequipamentos", request.client, resultados_ping)
        #return json.dumps(resultados_ping, indent=4) # indent=4 para formatação legível
        return respPadrao("SUCCESS",resultados_ping) # indent=4 para formatação legível

    except Exception as e:
        print(f"Ocorreu um erro geral: {e}")
        await bdLog("statusequipamentos", request.client, {"error": f"Erro interno: {str(e)}"})
        return respPadrao("ERROR",{"error": f"Erro interno: {str(e)}"})

#lastUpdate = time.ctime(os.path.getmtime(api_f))
lastUpdate = sys.version

BASE_DIR = Path(__file__).resolve().parent

app.mount("/imgs", StaticFiles(directory=str(Path(BASE_DIR, 'imgs'))), name="imgs")
templates = Jinja2Templates(directory=str(Path(BASE_DIR, 'templates')))

def respPadrao(model,lista):
    resp = {"task": model}
    if model == "ERROR":
        resp["ERROR"] = lista
    elif "SUCCESS":
        resp["resp"] = lista
    elif "PARSE":
        resp["PARSE"] = lista
    return resp

def listaIpEqs():
    #subnet = mIp.ipemask()
    #loop = asyncio.get_event_loop()
    subnet = get_network_info()["ip"] + "/24"
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


@app.get("/status")
async def status():
    """
    Endpoint para verificar o status da API.

    Retorna:
        dict: Um dicionário com a chave 'status' e o valor 'API is running'.
    """
    await bdLog("GET","status","Verificação de status realizada com sucesso.")
    return respPadrao("SUCCESS",{"status": "online"})

@app.get("/index", response_class=HTMLResponse)
async def create_index(request: Request):
    context = {'request': request, 'lastUpdate': lastUpdate}
    await bdLog("GET","index","Acesso a pagina index")
    return templates.TemplateResponse("index.html", context)


@app.get("/findEqs")
async def procurar_eqs(req: str = "vazio"):
    print("INFO: Commando feqs recebido")
    db_eq.reload()
    #LISTAR IP DE EQS REGISTRADOS
    nlist = []
    for eq in db_eq.register:
        nlist.append(eq["ip"])
    #LISTAR IPS DE EQS NA REDE
    nlist2 = listaIpEqs()
    
    dif = [ip for ip in nlist2 if ip not in nlist]
    
    resp = {"novosEqs": dif}
    
    eqsAcadastrar = Equipament()
    
    for ipx in dif:
        eqsAcadastrar.ip = ipx
        cadEqs2(eqsAcadastrar)
        
    await bdLog("GET","findEqs",req)
    return respPadrao("SUCCESS",resp)

@app.get("/cadastro_eq")
async def create_listEq(id: str = "0000"):
    idProcurado = id
    db_eq.reload()
    if idProcurado == "0000":
        listarEqs = db_eq.register
    else:
        listarEqs = db_eq.findbyid(idProcurado)
        await bdLog("GET","cadastro_eq",id)
        return respPadrao("SUCCESS",listarEqs)
    
    for pos in listarEqs:
        vl = yd.payLogin(pos["ip"])
        
        if vl:
            jsonResp = yd.eqInfo(pos["ip"])
            posBd = db_eq.findbyid(pos["id"])
            db_eq.editregister(posBd,"device_hostname", jsonResp["network"]["device_hostname"])
            pos["status"] = "Online"
        else:
            pos["status"] = "Offline"

        yd.logout(pos["ip"])
    
    await bdLog("GET","cadastro_eq",id)
    return respPadrao("SUCCESS",listarEqs)

@app.get("/cadastro_cl")
async def create_listEq(idYD: str = "vazio"):
    id = idYD
    db_cl.reload()
    if id != "0000":
        pos = db_cl.findbyid(id)
        if pos == -1:
            listaCls = {"lista": "lista vazia"}
            return respPadrao("SUCCESS",listaCls)
        else:
            listaCls = db_cl.register[pos]
            return respPadrao("SUCCESS",listaCls)
    else:
        listaCls = db_cl.register
    
    await bdLog("GET","cadastro_eq",id)
    return respPadrao("SUCCESS",listaCls)

###################### POST CADASTRAR EQUIPAMENTO #############
def cadEqs2(soli: Equipament):
    novo_cadastro = {}
    if soli.ip == None:
        return respPadrao("ERROR","Campo ip, obrigatorio")
    #test Duplicidade
    for eq in db_eq.register:
        if eq["ip"] == soli.ip:
            return respPadrao("ERROR",retERRORjson[1])

    #test existencia do ip
    vl = yd.payLogin(soli.ip)
    if vl == 0:
        return respPadrao("ERROR",retERRORjson[2])

    if soli.device_hostname != None:
        yd.updateDevice(soli.ip,soli.device_hostname)
    
    ret = yd.eqInfo(soli.ip)
    
    novo_cadastro["ip"] = soli.ip
    novo_cadastro["mac"] = ret["network"]["mac"]
    novo_cadastro["device_hostname"] = ret["network"]["device_hostname"]
    novo_cadastro["device_id"] = ret["device_id"]

    cadEq = equipament(novo_cadastro)
    db_eq.addregister(cadEq)
    
    ### Realizar configurações iniciciais ####
    ### ADD User for adm ###
    userFadm = yd.addUser(soli.ip,"Administrador","1","6584","13-03-2024 11:00:00","13-03-2028 11:00:00")
    userFadm = json.loads(userFadm)
    ### ativar envio de logs para central ####
    yd.activeLogs(soli.ip,get_network_info()["ip"],443)
    ### Setar hora conforme servidor ####
    yd.setTime(soli.ip)
    ### ADD Admin   ###
    yd.adduserAdm(soli.ip,userFadm["ids"][0],1)
    ### ADD Logo    ###
    yd.addLogo(soli.ip)
    ### ADD Sounds  ###
    # yd.soundCustom(soli.ip)
    # yd.addSoundMessage(soli.ip)
    ### Active Door Sensor  ###
    yd.activeSensor(soli.ip,"1","5")
    yd.logout(soli.ip)
    
    client = MongoClient(
            MONGO_HOST,
            MONGO_PORT,
            serverSelectionTimeoutMS=5000,
            directConnection=True
        )
    
    db = client[DATABASE_NAME]
    mondb_centrais = db["centrais_2_1"]
    Mondb_eq = db["equipamentos_2_1"]
    # Mongo DB
    filtro = {"device_id":novo_cadastro["device_id"]}
    testeExistencia = Mondb_eq.find_one(filtro)
    if testeExistencia is None:
        meuip = get_network_info("wg-client")["ip"]
        novo_cadastro["central_id"] = f"http://{meuip}:557"
        filtro2 = {"ipCentralMRD":novo_cadastro["central_id"]}
        mondb_centraisGet = mondb_centrais.find_one(filtro2)
        if mondb_centraisGet is not None:
            novo_cadastro["idCentral"] = mondb_centraisGet["_id"]
        else:
            novo_cadastro["idCentral"] = ""
        novo_cadastro["id"] = novo_cadastro["device_id"]
        novo_cadastro["__v"] = 0
        result = Mondb_eq.insert_one(novo_cadastro)
        print(f"Documento inserido com ID: {result.inserted_id}")
    
    client.close()
    return respPadrao("SUCCESS",novo_cadastro)

@app.post("/mirrored")
async def mirror(soli: ComunGeneric):
    try:
        fromdev_lc = soli.fromDev
        todev_lc = soli.toDev
    except:
        resp = "Falta de parametros fromDev e/ou toDev"
        await bdLog("POST","mirrored",soli)
        return respPadrao("SUCCESS",resp)
    
    resp = {"PARSE": [],
            "ERROR": [],
            "SUCCESS": []}
    
    ########## Listar clientes do eq FROM ############
    listClients_From = db_cl.findbyeq(fromdev_lc)
    for clientFrom in listClients_From:
        #### adicionar acesso "to" no cliente #######
        nListaAcesso = []
        add = True
        for clientFromAc in clientFrom["acessos"]:
            nListaAcesso.append(clientFromAc["device_id"])
            if (clientFromAc["device_id"] == todev_lc):
                add = False
        
        ### adicionar acesso to no cliente from
        if (add): nListaAcesso.append(todev_lc)
        
        clientFrom["acessos"] = nListaAcesso
        cliClass = Client()
        cliClass.id = clientFrom["id"]
        cliClass.name = clientFrom["name"]
        cliClass.idYD = clientFrom["idYD"]
        cliClass.password = clientFrom["password"]
        cliClass.begin_time = clientFrom["begin_time"]
        cliClass.end_time = clientFrom["end_time"]
        cliClass.acessos = clientFrom["acessos"]
        cliClass.bio = clientFrom["bio"]
        cliClass.base64 = clientFrom["base64"]
        
        #### Executar funcao update de clientes do from, colocando novo acesso
        rp = update_cad_cl(cliClass)
        
        if rp["task"] == "PARSE":
            resp["PARSE"].append(rp["PARSE"])
        elif rp["task"] == "ERROR":
            resp["ERROR"].append(rp["ERROR"])
        else:
            resp["SUCCESS"].append(rp["resp"])
    
    await bdLog("POST","mirrored",soli)
    if len(resp["PARSE"]) == 0 and len(resp["ERROR"]) == 0:
        return respPadrao("SUCCESS",resp["SUCCESS"])
    
    if len(resp["SUCCESS"]) == 0 and len(resp["ERROR"]) == 0:
        return respPadrao("PARSE",resp["PARSE"])
    
    if len(resp["SUCCESS"]) == 0 and len(resp["PARSE"]) == 0:
        return respPadrao("ERROR",resp["ERROR"])
    
    return respPadrao("SUCCESS",resp)

@app.post("/setEqTime")
async def setTimeEq(soli: Equipament):
    try:
        ip_loc = soli.ip
    except:
        await bdLog("POST","setEqTime",soli)
        return respPadrao("ERROR", "Falta de parametro ip")
    resp = {}
    vl = yd.payLogin(ip_loc)
    
    if vl == 0:
        await bdLog("POST","setEqTime",soli)
        return respPadrao("ERROR",retERRORjson[2])
    
    yd.setTime(ip_loc)
    yd.logout(ip_loc)
    await bdLog("POST","setEqTime",soli)
    return respPadrao("SUCCESS", resp)


################## POST CADASTRAR CLIENTE #######################

@app.post("/cadastro_cl")
async def incluir_novo_cadastro_cl(soli: Client):
    cadastrodecliente = soli

    #test Duplicidade
    if db_cl.findbyid(cadastrodecliente.idYD) != -1:
        await bdLog("POST","cadastro_cl",soli)
        return retERRORjson[3]

    #se todos dispositivos validos realizando cadastros
    acessosDict = []
    errorsCont = 0
    arrayOff = []
    for portas in cadastrodecliente.acessos:
        bdeqLoc = db_eq.findbyid(portas)
        if bdeqLoc == -1:
            errorDict = {"device_id": "0", "status": "0"}
            errorDict["device_id"] = portas
            errorDict["status"] = "faceid nao cadastrado"
            arrayOff.append(errorDict)
            errorsCont += 1
            continue
        ip = db_eq.register[bdeqLoc]["ip"]
        vl = yd.payLogin(ip)
        if vl == 0:
            errorDict = {"device_id": "0", "status": "0"}
            errorDict["device_id"] = portas
            errorDict["status"] = "offline"
            arrayOff.append(errorDict)
            errorsCont += 1
        else:
            ret = '{"ids": "00"}'
            jsonValues = yd.loadUsers(ip)
            clCad = False
            
            if jsonValues["users"] == []:
                ret = yd.addUser(ip,cadastrodecliente.name,cadastrodecliente.idYD,cadastrodecliente.password,cadastrodecliente.begin_time,cadastrodecliente.end_time)
                if ret == "ERROR IN_DATA":
                    await bdLog("ERROR_POST","cadastro_cl",soli)
                    return respPadrao("ERROR", ret)
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
                ret = yd.addUser(ip,cadastrodecliente.name,cadastrodecliente.idYD,cadastrodecliente.password,cadastrodecliente.begin_time,cadastrodecliente.end_time)
                if ret == "ERROR IN_DATA":
                    await bdLog("ERROR_POST","cadastro_cl",soli)
                    return respPadrao("ERROR", ret)

            ret = json.loads(ret)

            acessosDict.append({"device_hostname": db_eq.register[bdeqLoc]["device_hostname"], "device_id": db_eq.register[bdeqLoc]["device_id"], "user_idDevice": ret["ids"][0]})
        
        yd.logout(ip)
    
    cadastrodecliente.acessos = acessosDict
    cadastrodecliente.bio = "none"
    cadastrodecliente.base64 = "none"
    cladd = client(cadastrodecliente.dict())
    db_cl.addregister(cladd)
    await bdLog("POST","cadastro_cl",soli)
    if errorsCont == 0:
        print(cadastrodecliente.dict())
        return respPadrao("SUCCESS",cadastrodecliente)
    else:
        return respPadrao("PARSE",arrayOff)
    

#######################################################################################

@app.post('/cad_bio')
async def cadastrarBio(soli: Client):
    cada_bio = soli

    try:
        b64img = cada_bio.base64
    except:
        await bdLog("ERROR_POST","cad_bio",soli)
        return respPadrao("ERROR",retERRORjson[6])

    clDb = db_cl.findbyid(cada_bio.idYD)
    if clDb == -1:
        await bdLog("ERROR_POST","cad_bio",soli)
        return retERRORjson[4]

    contOff = 0
    arrayOff = []
    respRet = []
    resp = []
    retCads = False
    for portas in db_cl.register[clDb]["acessos"]:
        bdeqLoc = db_eq.findbyid(portas["device_id"])
        if bdeqLoc == -1:
            arrayOff.append(retERRORjson[2])
            contOff += 1
            continue

        vl = yd.payLogin(db_eq.register[bdeqLoc]["ip"])
        if vl == 0:
            db_cl.editregister(clDb,"bio","none")
            tmpVar = {"device_id": db_eq.register[bdeqLoc]["device_hostname"], "status": "Offline"}
            arrayOff.append(tmpVar)
            contOff += 1
        else:
            bdUsers = yd.loadUsers(db_eq.register[bdeqLoc]["ip"])
            for user in bdUsers["users"]:
                if user["registration"] == cada_bio.idYD:
                    userIdinPorta = user["id"]
                    break
            
            c = datetime.now()
            
            if userIdinPorta == None:
                tmpVar = {"device_ip": db_eq.register[bdeqLoc]["ip"], "ERROR": "user nao encontrado"}
                arrayOff.append(tmpVar)
                contOff += 1
            else:
                current_time = c.strftime('%d-%m-%Y %H:%M:%S')
                resp = yd.imageUpdt(db_eq.register[bdeqLoc]["ip"],userIdinPorta,b64img,current_time)
                yd.logout(db_eq.register[bdeqLoc]["ip"])
                
            if resp["success"] == True:
                retCads = True
                db_cl.editregister(clDb,"bio","cadastrada")
                db_cl.editregister(clDb,"base64",b64img)
                resp = {"device_id": portas["device_id"], "success": True}
                respRet.append(resp)
            else:
                if retCads == False:
                    db_cl.editregister(clDb,"bio","none")
                    db_cl.editregister(clDb,"base64","none")
                    resp = {"device_id": portas["device_id"], "success": False}
                    respRet.append(resp)
    
    await bdLog("ERROR_POST","cad_bio",soli)
    if contOff>=1:
        return respPadrao("ERROR",arrayOff)
    else:
        return respPadrao("SUCCESS",respRet)

def update_cad_cl(soli: Client):
    updateCl = soli
    arrayOff = []
    aceList = []
    errorsCont = 0
    #testando Json.
    try:
        idYD = updateCl.idYD
        if idYD == None:
            return respPadrao("ERROR",retERRORjson[0])
    except:
        return respPadrao("ERROR",retERRORjson[0])
    
    nameCl = updateCl.name
    passw = updateCl.password
    bTime = updateCl.begin_time
    eTime = updateCl.end_time
    acess = updateCl.acessos
    base64 = updateCl.base64
    
    pos = db_cl.findbyid(idYD)
    
    if nameCl == None:
        nameCl = db_cl.register[pos]["name"]
    
    if passw == None:
        passw = db_cl.register[pos]["password"]
    
    if bTime == None:
        bTime = db_cl.register[pos]["begin_time"]
    
    if eTime == None:
        eTime = db_cl.register[pos]["end_time"]
    
    if acess == None:
        acess = [u["device_id"] for u in db_cl.register[pos]["acessos"]]
    
    if base64 == None:
        base64 = db_cl.register[pos]["base64"]
        
    updateCl.name = nameCl
    updateCl.password = passw
    updateCl.begin_time = bTime
    updateCl.end_time = eTime
    updateCl.acessos = acess
    updateCl.base64 = base64
    
    # try:
    #     base64 = updateCl.base64
    #     updateCl.bio = "cadastrada"
    # except:
    #     updateCl.bio = db_cl.register[clAtual]["bio"]
    #     updateCl.base64 = db_cl.register[clAtual]["base64"]
    
    #Verificar existencia do usuário
    db_cl.reload()
    vlTest = db_cl.findbyid(idYD)
    if vlTest == -1:
        respostaN = {"ERRO:": "Cliente inexistente"}
        return respostaN
    
    #Verificar se houve remocao de acesso:
    listaAcActive = [x["device_id"] for x in db_cl.register[vlTest]["acessos"]]
    acess.sort()
    listaAcActive.sort()
    #novo  !=  antigo
    if acess != listaAcActive:
        for ac in listaAcActive:
            #compara lista actual do registro com lista nova
            if ac not in acess:
                bdeqLoc = db_eq.findbyid(ac)
                ip = db_eq.register[bdeqLoc]["ip"]
                vl = yd.payLogin(ip)
                if vl:
                    bdUsers = yd.loadUsers(ip)
                    userActve = [u for u in bdUsers["users"] if u['registration'] == idYD]
                    #Em caso de cadastro nao existir no equipamento
                    if userActve != []:
                        for us in userActve:
                            yd.delUser(ip,us["id"])
                else:
                    errorDict = {"device_id": "0", "status": "0"}
                    errorDict["device_hostname"] = db_eq.register[bdeqLoc]["device_hostname"]
                    errorDict["device_id"] = db_eq.register[bdeqLoc]["device_id"]
                    errorDict["status"] = "offline"
                    arrayOff.append(errorDict)
                    errorsCont += 1
                    
                yd.logout(ip)
     
    #procurando pelo id em cada acesso para atualizar
    for portas in acess:
        posEq = db_eq.findbyid(portas)
        ip = db_eq.register[posEq]["ip"]
        vl = yd.payLogin(ip)
        if vl == 0:
            errorDict = {"device_id": "0", "status": "0"}
            errorDict["device_id"] = portas
            errorDict["status"] = "offline"
            arrayOff.append(errorDict)
            errorsCont += 1
        else:
            bdUsers = yd.loadUsers(ip)
            userActve = [u for u in bdUsers["users"] if u['registration'] == idYD]
            c = datetime.now()
            current_time = c.strftime('%d-%m-%Y %H:%M:%S')
            #Em caso de cadastro nao existir no equipamento
            if userActve == []:
                ret =yd.addUser(ip,nameCl,idYD,passw,bTime,eTime)
                if ret == "ERROR IN_DATA":
                    return respPadrao("ERROR", ret)
                bdUsers = yd.loadUsers(ip)
                userActve = [u for u in bdUsers["users"] if u['registration'] == idYD]
                resp2 = yd.imageUpdt(ip,userActve[0]["id"],base64,current_time)
            else:
                yd.updateUser(ip,userActve[0]["id"],nameCl,idYD,passw,bTime,eTime)
                resp2 = yd.imageUpdt(ip,userActve[0]["id"],base64,current_time)

            aceList.append({
                "device_hostname": db_eq.register[posEq]["device_hostname"],
                "device_id": db_eq.register[posEq]["device_id"],
                "user_idDevice": userActve[0]["id"]
            })
            yd.logout(ip)

    clAtual = db_cl.findbyid(idYD)
    updateCl.acessos = aceList
    clADD = client(updateCl.dict())
    if base64 != "none" and base64 != None:
        clADD.base64 = base64
    db_cl.removeregisterbypos(clAtual)
    db_cl.addregister(clADD)
    clAtual = db_cl.findbyid(idYD)
    resp = db_cl.register[clAtual]
    
    if errorsCont>=1:
        return respPadrao("PARSE",arrayOff)
    else:
        return respPadrao("SUCCESS",resp)

@app.post('/atualiza_cl')
async def update_cad(soli: Client):
    resp = update_cad_cl(soli)
    await bdLog("POST","atualiza_cl",soli)
    return resp

# @app.post('/insertBckupCl')
# async def insertClientBckp(file: bytes = File()):
#     ret = {'desc': 'arquivo recebido','tamanho': len(file)}
#     with open(db_cl_f, 'wb') as f:
#         f.write(file)
#     return ret

# @app.post('/insertBckupEq')
# async def insertEqBckp(file: bytes = File()):
#     ret = {'desc': 'arquivo recebido','tamanho': len(file)}
#     with open(db_eq_f, 'wb') as f:
#         f.write(file)
#     return ret

#/########################################################################################/
#/######################################### PUT ##########################################/
#/########################################################################################/


#/PUT CLIENTES#
@app.put('/addAdmin')
async def addAdmin(soli: Client):
    try:
        idYd = soli.idYD
        acessos = soli.acessos
        admin = soli.admin
    except:
        await bdLog("ERROR_PUT","addAdmin",soli)
        return respPadrao("ERROR",retERRORjson[0])

    #verificar se eqs onLine returna array[on], array[off]
    arrayOn = []
    arrayOff = []
    for eqs in acessos:
        posdadosEq = db_eq.findbyid(eqs)
        idDoEq = db_eq.register[posdadosEq]["id"]
        ipDoEq = db_eq.register[posdadosEq]["ip"]
        eqD = {}
        if yd.testOnEq(ipDoEq):
            eqD["id"] = idDoEq
            eqD["ip"] = ipDoEq
            arrayOn.append(eqD)
        else:
            eqD["id"] = idDoEq
            eqD["ip"] = ipDoEq
            arrayOff.append(eqD)
    
    for eqsOn in arrayOn:
        vl = yd.payLogin(eqsOn["ip"])
        if vl:
            bdUsers = yd.loadUsers(eqsOn["ip"])
            usersExistInEq = [u for u in bdUsers["users"] if u['registration'] == idYd]
            ### FAZER: EM CASO DE MAIS DE UM USUARIO COM MESMO idYd - APAGAR USARIO #########################################
            for userInEq in usersExistInEq:
                yd.adduserAdm(eqsOn["ip"],userInEq["id"],admin)
        else:
            arrayOn.remove(eqsOn)
            arrayOff.append(eqsOn)    
    
    arrayResp = {'eqsOn':arrayOn,'eqsOff':arrayOff}
    
    await bdLog("PUT","addAdmin",soli)
    if len(arrayOff) == 0:
        return respPadrao("SUCCESS",arrayResp)
    elif len(arrayOn == 0):
        return respPadrao("ERROR",arrayResp)
    else:
        return respPadrao("PARSE",arrayResp)

#/PUT EQUIPAMENTOS#
@app.put('/cadastro_eq')
async def udate_eq(soli: Equipament):
    updateEQ = soli
    try:
        id = updateEQ.id
        ip = updateEQ.ip
        device_hostname = updateEQ.device_hostname
    except:
        await bdLog("ERROR_PUT","cadastro_eq",soli)
        return respPadrao("ERROR",retERRORjson[0])

    value2edit = db_eq.findbyid(id)
    if value2edit == -1:
        respostaN = "Equipamento inexistente"
        await bdLog("ERROR_PUT","cadastro_eq",soli)
        return respPadrao("ERROR",respostaN)

    if yd.payLogin(ip) == 0:
        await bdLog("ERROR_PUT","cadastro_eq",soli)
        return respPadrao("ERROR",retERRORjson[8])

    novo_cadastro = {}
    yd.updateDevice(soli.ip,device_hostname)
    
    yd.payLogin(ip)
    ret = yd.eqInfo(soli.ip)
    yd.logout(soli.ip)
    novo_cadastro["ip"] = soli.ip
    novo_cadastro["mac"] = ret["network"]["mac"]
    novo_cadastro["device_hostname"] = ret["network"]["device_hostname"]
    novo_cadastro["device_id"] = ret["device_id"]

    db_eq.editregister(value2edit,"device_id",ret["device_id"])
    db_eq.editregister(value2edit,"device_hostname",novo_cadastro["device_hostname"])
    db_eq.editregister(value2edit,"mac",novo_cadastro["mac"])
    db_eq.editregister(value2edit,"ip",novo_cadastro["ip"])
    await bdLog("PUT","cadastro_eq",soli)
    return respPadrao("SUCCESS",novo_cadastro)

#/########################################################################################/
#/######################################### DELETE #######################################/
#/########################################################################################/

def fc_del_idYD_eq(soli: ComunGeneric):
    try:
        idYD_Loc = soli.idYD
        device_id_Loc = str(soli.device_id)
        if soli.debug != None:
            print("DEBUG: ",soli.debug)
            return respPadrao("DEBUG",soli.debug)
    except:
        return respPadrao("ERROR", "Falta de parametros idYD e/ou device_id")
    
    posCl = db_cl.findbyid(idYD_Loc)
    nAcessos = []
    for acessos in db_cl.register[posCl]["acessos"]:
        if acessos["device_id"] != device_id_Loc:
            nAcessos.append(acessos["device_id"])
            
    ### adicionar acesso to no cliente from
    
    cliClass = Client()
    cliClass.id = db_cl.register[posCl]["id"]
    cliClass.name = db_cl.register[posCl]["name"]
    cliClass.idYD = db_cl.register[posCl]["idYD"]
    cliClass.password = db_cl.register[posCl]["password"]
    cliClass.begin_time = db_cl.register[posCl]["begin_time"]
    cliClass.end_time = db_cl.register[posCl]["end_time"]
    cliClass.acessos = nAcessos
    cliClass.bio = db_cl.register[posCl]["bio"]
    cliClass.base64 = db_cl.register[posCl]["base64"]
    
    #### Executar funcao update de clientes do from, colocando novo acesso
    rp = update_cad_cl(cliClass)
    
    return rp

@app.delete('/del_idYD_eq')
async def del_idYD_eq(soli: ComunGeneric):
    await bdLog("DELETE","del_idYD_eq",soli)
    rp = fc_del_idYD_eq(soli)
    return rp

@app.delete('/del_eq')
async def del_cadastros_eq(soli: Equipament):
    try:
        pos = db_eq.findbyid(soli.device_id)
    except:
        await bdLog("ERROR_DELETE","del_eq",soli)
        return respPadrao("ERROR",retERRORjson[0])

    clasCom = ComunGeneric()
    listCl = db_cl.findbyeq(soli.device_id)
    for client in listCl:
        clientPos = db_cl.findbyid(client)
        clientDat = db_cl.register[clientPos]
        clasCom.idYD = clientDat["idYD"]
        clasCom.device_id = soli.device_id
        fc_del_idYD_eq(clasCom)
    
    # ip = db_eq.register[pos]["ip"]
    # yd.payLogin(ip)
    # make = True
    # try:
    #     yd.fabricReset(ip)
    #     make = False
    # except:
    #     pass
    
    # if make: yd.logout(ip)
    
    # Mondb_eq.delete_one({"device_id":soli.device_id})
    
    db_eq.removeregisterbypos(pos)
    await bdLog("DELETE","del_eq",soli)
    return respPadrao("SUCCESS",db_eq.register)

@app.delete('/del_cl')
async def del_cadastro_cl(soli: Client):
    try:
        cadastrodecliente = soli.idYD
    except:
        await bdLog("ERROR_DELETE","del_cl",soli)
        return respPadrao("ERROR",retERRORjson[0])
    
    cadastrodecliente = soli
    clDb = db_cl.findbyid(cadastrodecliente.idYD)

    if clDb == -1:
        myResp = {"code": "ERROR", "desc": "Cliente nao encontrado"}
        await bdLog("ERROR_DELETE","del_cl",soli)
        return respPadrao("ERROR",myResp)

    arrayOff = []
    errorsCont = 0
    for portas in db_cl.register[clDb]["acessos"]:
        bdeqLoc = db_eq.findbyid(portas["device_id"])
        ip = db_eq.register[bdeqLoc]["ip"]
        vl = yd.payLogin(ip)
        if vl:
            bdUsers = yd.loadUsers(ip)
            userActve = [u for u in bdUsers["users"] if u['registration'] == cadastrodecliente.idYD]

            #Em caso de cadastro nao existir no equipamento
            if userActve == []:
                myResp = {"code": "ERROR", "desc": "cliente nao cadastrado no acesso"}
                db_cl.removeregisterbypos(clDb)
            else:
                for us in userActve:
                    yd.delUser(ip,us["id"])
            
            yd.logout(ip)
        else:
            errorDict = {"device_id": "0", "status": "0"}
            errorDict["device_hostname"] = portas["device_hostname"]
            errorDict["device_id"] = portas["device_id"]
            errorDict["status"] = "offline"
            arrayOff.append(errorDict)
            errorsCont += 1

    if errorsCont>=1:
        allAcessos = db_cl.register[clDb]["acessos"]
        newAcessos = []
        for ac in allAcessos:
            if ac["device_id"] not in allAcessos:
                newAcessos.append(ac)
        db_cl.editregister(clDb,"acessos",newAcessos)
        await bdLog("ERROR_DELETE","del_cl",soli)
        return respPadrao("PARSE",arrayOff)
    else:
        db_cl.removeregisterbypos(clDb)
    
    lista_cl = db_cl.findbyid(cadastrodecliente.idYD)
    if lista_cl == -1:
        dictVal = {"desc": "Removido com sucesso"}
    else:
        dictVal = lista_cl
    
    await bdLog("DELETE","del_cl",soli)
    return respPadrao("SUCCESS",dictVal)

# @app.post('/teste')
# async def teste(soli: Equipament):
#     yd.payLogin(soli.ip)
#     ret = yd.loadRules(soli.ip)
#     return ret

if __name__ == '__main__':
    #logging.basicConfig(
    #    level=logging.ERROR,
    #    format="%(asctime)s - %(levelname)s - %(message)s",
    #    handlers=[logging.FileHandler("logs/api.log")],
    #)
    
    print("Servidor inicializado... - Listening")
    #uvicorn.run(app, host='0.0.0.0', port=443)
    uvicorn.run(app, host='0.0.0.0', port=557)