import socket
import time
from datetime import datetime
# валидация ip
from ipaddress import IPv4Address, AddressValueError
from pprint import pprint


# info from whois.iana.org
def iana(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('whois.iana.org', 43))
    s.send((ip + '\r\n').encode())
    response = b''
    while True:
        data = s.recv(4096) # данные из сокета
        response += data
        if not data:
            break
    s.close()
    whois = ''
    for resp in response.decode().splitlines():
        if resp.startswith('%') or not resp.strip():
            continue
        elif resp.startswith('whois'):
            whois = resp.split(':')[1].strip()
            break
    return whois if whois else False


# get info from ip
def get_whois(ip, whois):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((whois, 43))
    s.send((ip + '\r\n').encode())
    response = b''
    while True:
        data = s.recv(4096)
        response += data
        if not data:
            break
    s.close()
    whois_ip = dict()
    num = 0
    
    for resp in response.decode().splitlines():
        if resp.strip().startswith('%') or not resp.strip():
            continue
        else:
            if resp.strip().split(": ")[0].strip() in ['created', 'last-modified']:
                dt = datetime.fromisoformat(resp.strip().split(":")[1].strip()).strftime("%Y-%m-%d %H:%M:%S")
                
                whois_ip.update({f"{resp.strip().split(': ')[0].strip()}_{num}": dt})
                num += 1
            else:
                whois_ip.update({resp.strip().split(': ')[0].strip(): resp.strip().split(': ')[1].strip()})
    return whois_ip if whois_ip else False


# валидируем адрес и обрабатываем ответы
def validate_request(ip):
    try:
        IPv4Address(ip)
        if whois := iana(ip):
            time.sleep(1)
            if info := get_whois(ip, whois):
                pprint(info)
            else:
                print('Не удалось получить данные об IP-адресе')
        else:
            print('Произошла ошибка! будет использован стандартный регистратор whois.ripe.net')
            if info := get_whois(ip, 'whois.ripe.net'):
                pprint(info)
            else:
                print('не удалось получить данные об IP-адресе')
    except AddressValueError:
        print('IP-адрес не валидный')
    except ConnectionRefusedError as ex:
        print(ex)

target = input('Введите IP-адрес цели: ')
pprint(get_whois(target, iana(target)))

