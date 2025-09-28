import requests,time
import json
from datetime import datetime, timedelta
from pathlib import Path
from pythonping import ping
import base64
import socket
from socket import AF_INET, SOCK_DGRAM
import struct
import pytz
import re

logoPng = Path(__file__).parent / 'logo_YouDO-1.png'
wavSound_Auth = Path(__file__).parent / 'msg_authorized.wav'
wavSound_NotAuth = Path(__file__).parent / 'msg_notauthorized.wav'

PASS_0 = "admin"
PASS_1 = "e3b0c44298f"

hostG = ""
mySession = ""

def headerJS():
    global headers
    global mySession
    global hostG
    headers = {
        'Content-Type': 'application/json'
    }

### FAZER LOGIN ####

def payLoginOLD(host):
    global mySession
    global hostG
    sysInfUrl = "http://{}/login.fcgi".format(host)
    payload = json.dumps({
        "login": "admin",
        "password": PASS_0
    })
    headerJS()
    host_ip = host.split(':')[0]
    
    try:
        result = ping(host_ip, count=1, timeout=1)
        if result.packet_loss >= 1:
            print(f"ERRO: Host {host_ip} inacessível (ping falhou).")
            return 0
    except Exception as e:
        print(f"ERRO: Falha ao executar o ping para {host_ip}. Detalhes: {e}")
        return 0
    #testAdrres = "http://{}".format(host)
    #testIp = requests.get(testAdrres)
    #if testIp.status_code != 200:
    #    return 0
    
    try:
        response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
        json_conv = json.loads(response.text)
        mySession = json_conv['session']
        hostG = host
        return 1
    except:
        return 0

def payLogin(host):
    global mySession
    global hostG
    
    headerJS()
    
    host_ip = host.split(':')[0]
    
    try:
        result = ping(host_ip, count=1, timeout=1)
        if result.packet_loss >= 1:
            print(f"ERRO: Host {host_ip} inacessível (ping falhou).")
            return 0
    except Exception as e:
        print(f"ERRO: Falha ao executar o ping para {host_ip}. Detalhes: {e}")
        return 0

    payload = json.dumps({
        "login": "admin",
        "password": PASS_1
    })

    urls_para_tentar = [
        f"http://{host_ip}:85/login.fcgi",
        f"http://{host_ip}/login.fcgi"
    ]

    response = None
    for url in urls_para_tentar:
        try:
            #print(f"INFO: Tentando conectar em {url}...")
            response = requests.request("POST", url, headers=headers, data=payload, timeout=5)
            #print(f"INFO: Conexão com {url} bem-sucedida.")
            #define o hostG com o hostip +85 se a porta 85 foi bem sucedida
            if url.endswith(":85/login.fcgi"):
                hostG = f"{host_ip}:85"
            else:
                hostG = host_ip
            break

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            #print(f"AVISO: Falha ao conectar em {url}. #3245")
            response = None # Garante que a resposta seja nula se a conexão falhar
    
    # Se, após o loop, a 'response' continuar nula, significa que todas as tentativas falharam.
    if response is None:
        #print(f"ERRO: Não foi possível estabelecer conexão com o host {host_ip} em nenhuma das portas (80, 85).")
        return 0

    try:
        json_conv = response.json() # Forma mais limpa de carregar o JSON
        if 'session' in json_conv:
            mySession = json_conv['session']
            return 1
        else:
            payLoginOLD(host)
            changePassword(host, PASS_1)
            setwebaccess(host, "0")
            print("INFO: Credenciais inválidas. A senha foi redefinida para o padrão.")
            return 2
        
    except json.JSONDecodeError:
        print(f"ERRO: A resposta do equipamento não é um JSON válido. Resposta: {response.text}")
        return 0

###### MEU IP NO SERVIDOR ######
def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # doesn't even have to be reachable
        s.connect(('192.168.101.1', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

# def getCentrais():
#     url = "http://177.71.174.32:10600/centrais"
#     headers = {
#         'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IllvdWRvb19NUkQiLCJuYW1lIjoiNTg3NDY5IiwiaWF0IjoxNzEzNzg5MzEwLCJleHAiOjE3MTQ2NTMzMTB9.NwPWdQHnj0wZV4LGHZ_jL6r71vcdYXLJPp9FH_70Km8'
#     }
#     payload=""
#     try:
#         response = requests.request("GET", url, headers=headers, data=payload)
#         json_conv = json.loads(response.text)
#     except:
#         return 0
    
#     for id in json_conv:
#         if id['ipCentralMRD'] == 'http://'+get_ip()+':443':
#             return id['_id']

###### ^^^^^^^^^^^^^^^^^^^^^^^#######
### FAZER LOGOUT ###
def logout(host):
    global mySession
    global hostG
    host = hostG
    if mySession == "" or mySession == None:
        return "NO SESSION"
    logoutUrl = "http://{}/logout.fcgi?session={}".format(host+":85",mySession)
    try:
        response = requests.request("POST", logoutUrl, headers={}, data={},timeout=3)
    except:
        try:
            logoutUrl = "http://{}/logout.fcgi?session={}".format(host,mySession)
            response = requests.request("POST", logoutUrl, headers={}, data={},timeout=3)
            return response.text
        except:
            return "LOGOUT ERROR"
    return response.text

### ABRIR PORTA ###
def payDoorOpen(host):
    host = hostG
    actionUrl = "http://{}/execute_actions.fcgi?session={}".format(host,mySession)
    payload = json.dumps({
        "actions": [
                {
                    "action": "sec_box",
                    "parameters": "id=65793,reason=3"
                }
            ]
    })
    headerJS()
    response = requests.request("POST", actionUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    try:
        error = json_conv['code']
        print("Nao deu abriu: {}\n".format(error))
    except KeyError:
        print("Porta Aberta!\n")

def addLogo(host):
    host = hostG
    sysInfUrl = "http://{}/logo_change.fcgi?session={}".format(host,mySession)
    with open(logoPng,'rb') as f:
        data = f.read()
    
    head={'Content-Type': 'application/octet-stream'}
    
    #response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    response = requests.post(sysInfUrl,data,headers=head)
    return response

def converter_para_int(texto: str) -> int:
    """
    Remove todos os caracteres não numéricos de uma string e a converte para inteiro.
    Retorna 0 se a string não contiver nenhum dígito.
    """
    if not isinstance(texto, str):
        return 0
        
    # Usando re.sub para substituir tudo que não é dígito (\D) por nada ('')
    apenas_digitos = re.sub(r'\D', '', texto)
    
    # Verifica se, após a limpeza, sobrou algum dígito
    if apenas_digitos:
        return int(apenas_digitos)
    else:
        # Retorna 0 se a string original não tinha nenhum número
        return 0

# Cadastrar usuário
# name as String - "amauri"
# idYd as String - "6545"
# passW as String - "ps346"
# bTime as String - "13-03-2024 11:00:00"
# eTime as String - "14-03-2024 11:00:00"
def addListUser(host,listaUser: list, listGroup: list):
    host = hostG
    sysInfUrl = "http://{}/create_objects.fcgi?session={}".format(host,mySession)
        
    payload = json.dumps({
        "object": "users",
        "values": listaUser
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    cadastrarUserNoGroupList(host,listGroup)
    return response.text

def addListimageUpdt(host,listaUserImg: list,timeStamp):
    host = hostG
    
    sysInfUrl = "http://{}/user_set_image_list.fcgi?session={}&timestamp={}".format(host,mySession,timeStamp)

    payload = json.dumps({
        "user_images": listaUserImg
    })
    
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

def addUser(host,name,idYd,passW,bTime,eTime):
    host = hostG
    sysInfUrl = "http://{}/create_objects.fcgi?session={}".format(host,mySession)
    
    passCont = gerarHash(host,passW)
    
    if passCont == ["error", "error"]:
        print("ERRO: Falha ao gerar hash da senha. Usuário não adicionado.")
        return "ERROR IN_PASS"
    # '31-06-2025 14:00:00'
    try:
        date_btstmp = datetime.strptime(bTime, "%d-%m-%Y %H:%M:%S")
        date_etstmp = datetime.strptime(eTime, "%d-%m-%Y %H:%M:%S")
    except:
        # "Formato de data inválido. Use 'dd-mm-yyyy HH:MM:SS'"
        return "ERROR IN_DATA"
    
    idYdN = converter_para_int(idYd)
        
    payload = json.dumps({
        "object": "users",
        "values": [
            {
            "id": idYdN,
            "name": name,
            "registration": idYd,
            "password": passCont[0],
            "salt": passCont[1],
            "begin_time": int(date_btstmp.timestamp() - 10800), # - 10800 13-03-2024 11:00:00 - 3hrs
		    "end_time": int(date_etstmp.timestamp() - 10800) #2019-12-31 21:00:00 - 3hrs
            }
        ]
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    try:
        userID = json_conv["ids"][0]
    except:
        return -1
    cadastrarUserNoGroup(host,userID,1)
    return response.text

#Tornar Usuario Admin
def adduserAdm(host,idUser,role):
    #role 1 para adm 0 para cl
    host = hostG
    usersEx = loadRules(host)
    userChange = False
    for user in usersEx["user_roles"]:
        if user["user_id"] == idUser:
            sysInfUrl = "http://{}/modify_objects.fcgi?session={}".format(host,mySession)
            payload = json.dumps({
                "object": "user_roles",
                "values": {
                    "role": role,
                },
                "where": {
                    "user_roles": {
                        "user_id": idUser
                    }
                }
            })
            userChange = True

    if not userChange:      
        sysInfUrl = "http://{}/create_objects.fcgi?session={}".format(host,mySession)

        payload = json.dumps({
            "object": "user_roles",
            "values":[
                {
                    "user_id": idUser,
                    "role": role
                }
            ]
        })
        
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

### OBTER IFORMACOES DO EQ ###
def eqInfo(host):
    global mySession
    host = hostG
    sysInfUrl = "http://{}/system_information.fcgi?session={}".format(host,mySession)
    payload = ""
    headers = {}
    
    try:
        response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    except:
        return 0
    
    json_conv = json.loads(response.text)
    #print(json_conv["network"]["mac"])
    #print(json_conv["network"]["ip"])
    #print(json_conv["memory"]["disk"]["free"])
    return json_conv

# -------------- Cadastrar usuário -------------
def gerarHash(host,passW):
    host = hostG
    sysInfUrl = "http://{}/user_hash_password.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "password": passW
    })
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        response = requests.request("POST", sysInfUrl, headers=headers, data=payload)

        json_conv = json.loads(response.text)
    except:
        print("ERRO: Resposta inesperada ao gerar hash.")
        return ["error","error"]
    #print(json_conv["password"])
    #print(json_conv["salt"])
    return [json_conv["password"], json_conv["salt"]]

def imageUpdt(host,userID,b64img,timeString):
    host = hostG
    try:
        date_bt = datetime.strptime(timeString, "%d-%m-%Y %H:%M:%S")
    except:
        date_bt = datetime.strptime(timeString, "%Y-%m-%d %H:%M:%S")

    timeStamp = int(date_bt.timestamp() - 10800)
    
    sysInfUrl = "http://{}/user_set_image.fcgi?session={}&user_id={}&timestamp={}&match=0".format(host,mySession,userID,timeStamp)
    
    try:
        imgN = base64.b64decode(b64img)
        payload = imgN
    except:
        return {"error": "Base64 decode failed"}
    
    headers = {
        'Content-Type': 'application/octet-stream'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv
    
def getImage(host,userID):
    host = hostG
    url = "http://{}/user_get_image.fcgi?session={}&user_id={}".format(host,mySession,userID)

    payload={}
    headers = {
        'Content-Type': 'image/jpeg'
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    #A imagem fica em response.content
    return response.content
    
#Carregar usuarios
def loadUsers(host):
    host = hostG
    sysInfUrl = "http://{}/load_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "object": "users"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

#Carregar usuario por id
def loadUsersById(host,id):
    host = hostG
    sysInfUrl = "http://{}/load_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "object": "users",
        "where": [{
              "object": "users",
              "field": "id",
              "operator": "=",
              "value": id          
          }]
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

#Carregar objRules
def loadRules(host):
    host = hostG
    sysInfUrl = "http://{}/load_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "object": "user_roles"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

#Carregar Device
def loadDevice(host):
    host = hostG
    sysInfUrl = "http://{}/load_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "object": "devices"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

#atualizar nome do faceid
def updateDevice(host,name):
    host = hostG
    sysInfUrl = "http://{}/set_system_network.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "custom_hostname_enabled": True,
        "device_hostname": name
    })
    headers = {
        "Content-Type": "application/json"
    }
    try:
        requests.request("POST", sysInfUrl, headers=headers, data=payload,timeout=1)
    except:
        json_conv = "Success"
    
    json_conv = "Success"
    return json_conv

def changePassword(host,newPass):
    host = hostG
    sysInfUrl = "http://{}/change_login.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "login": "admin",
        "password": newPass
    })
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        requests.request("POST", sysInfUrl, headers=headers, data=payload,timeout=1)
        json_conv = "Success"
    except:
        json_conv = "Error"
    
    return json_conv
        
#Atualizar cadastro de usuario
def updateUser(host,id,name,idYd,passW,bTime,eTime):
    host = hostG
    sysInfUrl = "http://{}/modify_objects.fcgi?session={}".format(host,mySession)
    passCont = gerarHash(host,passW)
    
    if passCont == ["error", "error"]:
        print("ERRO: Falha ao gerar hash da senha. Usuário não adicionado.")
        return "ERROR IN_PASS"
    
    try:
        if isinstance(bTime, int):
            date_btstmp = datetime.fromtimestamp(bTime) #bTime
        else:
            date_btstmp = datetime.strptime(bTime, "%d-%m-%Y %H:%M:%S")
        if isinstance(eTime, int):
            date_etstmp = datetime.fromtimestamp(eTime) #eTime
        else:
            date_etstmp = datetime.strptime(eTime, "%d-%m-%Y %H:%M:%S")
    except:
        date_btstmp = datetime.strptime(bTime, "%Y-%m-%d %H:%M:%S")
        date_etstmp = datetime.strptime(eTime, "%Y-%m-%d %H:%M:%S")
    
    payload = json.dumps({
        "object": "users",
        "values": {
            "name": name,
            "registration": idYd,
            "password": passCont[0],
            "salt": passCont[1],
            "begin_time": int(date_btstmp.timestamp() - 10800), #13-03-2024 11:00:00 - 3hrs  - 10800
		    "end_time": int(date_etstmp.timestamp() - 10800) #2019-12-31 21:00:00 - 3hrs - 10800
        },
        "where": {
            "users": {
                "id": id
            }
        }
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv
    

#Deletar usuario
def delUser(host,id):
    host = hostG
    sysInfUrl = "http://{}/destroy_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "object": "users",
        "where": {
        "users": {
        "id": id
        }
    }
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

#reset de fabrica
def fabricReset(host):
    host = hostG
    print(host)
    sysInfUrl = "http://{}/reset_to_factory_default.fcgi?session={}".format(host,mySession)

    payload = json.dumps({})
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

def restartDevice(host):
    host = hostG
    sysInfUrl = "http://{}/reboot.fcgi?session={}".format(host,mySession)

    payload = json.dumps({})
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

#Setar horario
def getNTPTime(host = "pool.ntp.org"):
    port = 123
    buf = 1024
    address = (host, port)
    msg = b'\x1b' + 47 * b'\0'

    TIME1970 = 2208988800

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        client.sendto(msg, address)
        client.settimeout(3)
        msg, address = client.recvfrom(buf)
    except socket.timeout:
        print("Erro: Timeout ao tentar conectar ao servidor NTP.")
        return None
    finally:
        client.close()

    t = struct.unpack("!12I", msg)[10]
    t -= TIME1970

    # --- CORREÇÃO PARA PYTHON 3.6 ---
    # 1. Cria um objeto datetime "naïve" (sem fuso) a partir do timestamp UTC.
    #    Este é o método que você usou originalmente e está correto para esta versão.
    utc_datetime = datetime.utcfromtimestamp(t)

    # 2. Define os fusos horários de UTC e de destino usando pytz.
    utc_tz = pytz.utc
    brasilia_tz = pytz.timezone('America/Sao_Paulo')

    # 3. "Localiza" o datetime ingênuo, tornando-o "aware" (consciente) de que é UTC.
    #    Este é o passo crucial ao usar pytz.
    aware_utc_datetime = utc_tz.localize(utc_datetime)

    # 4. Converte o datetime UTC "aware" para o fuso de Brasília.
    brasilia_datetime = aware_utc_datetime.astimezone(brasilia_tz)

    df = {
        'day': brasilia_datetime.day,
        'month': brasilia_datetime.month,
        'year': brasilia_datetime.year,
        'hour': brasilia_datetime.hour,
        'minute': brasilia_datetime.minute,
        'second': brasilia_datetime.second
    }

    return df
    
def setTime(host):
    host = hostG
    sysInfUrl = "http://{}/set_system_time.fcgi?session={}".format(host,mySession)

    # {"day": 21,  "month": 8,  "year": 2019,  "hour": 0,  "minute": 59,  "second": 50}
    dicValue = getNTPTime()
    payload = json.dumps(dicValue)
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

def loadGroups(host):
    host = hostG
    sysInfUrl = "http://{}/load_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
        "object": "groups"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

def cadastrarUserNoGroup(host,userID,groupID):
    host = hostG
    sysInfUrl = "http://{}/create_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
    "object": "user_groups",
    "fields": [
        "user_id",
        "group_id"
    ],
    "values": [
        {
        "user_id": userID,
        "group_id": groupID
        }
    ]
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    return response

def cadastrarUserNoGroupList(host,userIDList: list):
    host = hostG
    sysInfUrl = "http://{}/create_objects.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
    "object": "user_groups",
    "fields": [
        "user_id",
        "group_id"
    ],
    "values": userIDList
    })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    return response

def soundCustom(host,authorized="default",notAuthorized="default"):
    host = hostG
    sysInfUrl = "http://{}/set_configuration.fcgi?session={}".format(host,mySession)

    payload = json.dumps({
            "buzzer": {
                "audio_message_not_identified": "default",
                "audio_message_authorized": authorized,
                "audio_message_not_authorized": notAuthorized,
                "audio_message_use_mask": "default"
            }
        })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

def addSoundMessage(host):
    host = hostG
    sysInfUrl = "http://{}/set_audio_access_message.fcgi?event=authorized&current=1&total=1&session={}".format(host,mySession)
    
    with open(wavSound_Auth,'rb') as f:
        data = f.read()
    
    head={'Content-Type': 'application/octet-stream'}
    
    #response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    response = requests.post(sysInfUrl,data,headers=head)
    
    sysInfUrl = "http://{}/set_audio_access_message.fcgi?event=not_authorized&current=1&total=1&session={}".format(host,mySession)
    
    with open(wavSound_NotAuth,'rb') as f:
        data = f.read()
    
    head={'Content-Type': 'application/octet-stream'}
    
    #response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    response = requests.post(sysInfUrl,data,headers=head)
    return response

def activeSensor(host,activeSensor,timeDelay):
    host = hostG
    sysInfUrl = "http://{}/set_configuration.fcgi?session={}".format(host,mySession)
    payload = json.dumps({
                "alarm": {
                    "door_sensor_enabled": activeSensor,
                    "door_sensor_delay": timeDelay
                }
                })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    response = sec_boxConfDoorSens(host)
    return response

def sec_boxConfDoorSens(host):
    host = hostG
    sysInfUrl = "http://{}/modify_objects.fcgi?session={}".format(host,mySession)
    
    payload = json.dumps({
        "object": "sec_boxs",
        "values": {
            "door_sensor_enabled": 1,
            "door_sensor_idle": 0
        }
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    json_conv = json.loads(response.text)
    return json_conv

def activeLogs(host,address,port,rqtimeout="5000"):
    host = hostG
    sysInfUrl = "http://{}/set_configuration.fcgi?session={}".format(host,mySession)
    payload = json.dumps({
                "monitor": {
                    "request_timeout": rqtimeout,
                    "hostname": address,
                    "port": port, # "443"
                    "path": "receivedatafromeqs"
                }
                })
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    return response.text

def setwebaccess(host,enable):
    #possibilidade https://www.controlid.com.br/docs/access-api-en/system/disable-web-interface/
    host = hostG
    host_ip = host.split(':')[0]
    headerJS()
    if enable == "0":
        host = host_ip
        payload = json.dumps({
            "web_server_port": 85
        })
    else:
        payload = json.dumps({
            "web_server_port": 80
        })
        
    sysInfUrl = "http://{}/set_system_network.fcgi?session={}".format(host,mySession)
    try:
        response = requests.request("POST", sysInfUrl, headers=headers, data=payload,timeout=3)
    except Exception as e:
        response = e
        #print(response)
        return response
    return response.text

def onlineMode(host,enable):
    host = hostG
    sysInfUrl = "http://{}/set_configuration.fcgi?session={}".format(host,mySession)
    if enable == "0":    
        payload = json.dumps({
            "general": [
                "online"]
        })
    else:
        payload = json.dumps({
            "general": {"online": "0"}
        })
        
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        response = requests.request("POST", sysInfUrl, headers=headers, data=payload)
    except:
        response = "error"
    return response.text

#json_conv = eqInfo(host)
#print(json_conv["network"]["mac"])
#print(json_conv["network"]["ip"])
#print(json_conv["memory"]["disk"]["free"])
#logout(host)

#addUser(host,mySession,"123Amauri458","56sd3","123123","13-03-2024 13:00:00","13-03-2024 18:00:00")
#nmap -sP 192.168.0.1/24
#Nmap scan report for 192.168.0.129
#Host is up (0.0045s latency).
#MAC Address: FC:52:CE:89:B3:86 (Control iD)
#crObjUrl = f"{host}/create_objects.fcgi?session={mySession}"
# teste = 2
# host = "192.168.0.228"
# if teste == 1:
#     z = payLoginOLD(host)
#     print("##00")
#     x = changePassword(host,"e3b0c44298f")
#     print("##01")
#     print(x)
#     print("##02")
#     x = setwebaccess(host,"0")
#     print(x)
#     logout(host)
#     print("##03")
#     x = payLogin(host)
#     print("##04")
#     res = addUser(host,"Administrador","1","1313","13-03-2024 11:00:00","13-03-2028 11:00:00")
#     res = adduserAdm(host,1,1)
#     res = setTime(host)
#     res = addLogo(host)
#     logout(host)
#     print("##05")
# else:
#     payLogin(host)
#     fabricReset(host)
#     logout(host)
# x = onlineMode(host,"1")
# setwebaccess(host,"0")
# x = activeSensor(host,"1","10")
# x = loadUsersById(host,243)
#print(z)
