import subprocess
import os
import requests
from celery import shared_task
from dashboard.celery import app
from time import sleep
from .models import FullScan, NucleiTrigger, NucleiScan, CrawlScan, Har, ZapScan, ZapTrigger, ProxyConfig
import json 
from urllib.parse import urlparse
import requests
import re
from bs4 import BeautifulSoup
from .middleware import SECRET_KEY
import sys
import time
import signal
import socket
import threading
import re
import argparse
import json
import random
import jwt 
BLACK_LIST = [".jsp", ".js", ".css", ".jpg", ".png", '.otf', '.xml', '.svg', '.gif', '.eot', '.ttf', '.woff','.woff2',
              ".ico", '.pdf', '.doc', '.docx']

SESSION_STORAGE = []
def test(ID):
    pass

with open("log.txt", "w") as f:
    f.write("")

def signal_handler(sig, frame):
    print('Proxy is Stopped.')
    sys.exit(0)

def write(*content, prt=False):
    if prt : 
        if len(content[0])<100:
            print(*content)
        else:
            print("This message is too long not print in cmd but will store at log.txt.")
    if type(content[0])==bytes:
        content = b" ".join(content)
    else:
        content = bytes(" ".join(content), encoding="utf-8")
    with open("log.txt", "ab") as f:
        f.write(content+b"\n")  

class Proxy:
    def __init__(self, port=7777, ip='127.0.0.1', sessions=[], auth_type='token' ):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # creating a tcp socket
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse the socket
        self.ip = ip
        self.port = port
        self.sessions = sessions
#         self.host = socket.gethostbyname(socket.gethostname())+":%s"%self.port
        self.sock.bind((self.ip, self.port))
        self.sock.listen(10)
        print("Proxy Server Is Start, See log.txt get log.")
        print("Press Ctrl+C to Stop.")
        start_multirequest = threading.Thread(target=self.multirequest)
        start_multirequest.setDaemon(True)
        start_multirequest.start()
        # while 1: это нужно раскоментить 
        #     time.sleep(0.01)
        #     signal.signal(signal.SIGINT, signal_handler)
    
    def get_random_cred(self):
        if len(self.sessions) >= 1:
            max_len = len(self.sessions)
            random_number = random.randint(0, max_len-2)
            return self.sessions[random_number]
        else:
            return None
        
    def get_random_tokens(self):
        print("SESSION STORAGE IS")
        if len(SESSION_STORAGE) >= 1:
            max_len = len(SESSION_STORAGE)
            random_number = random.randint(0, max_len-2)
            return SESSION_STORAGE[random_number]
        else:
            return None
        
    def multirequest(self):
        while True:
            (clientSocket, client_address) = self.sock.accept() # establish the connection
            client_process = threading.Thread(target=self.main, args=(clientSocket, client_address))
            client_process.setDaemon(True)
            client_process.start()
            
    def main(self, client_conn, client_addr): # client_conn is the connection by proxy client like browser.
        origin_request = client_conn.recv(4096)

        request = origin_request.decode(encoding="utf-8") # get the request from browser
        print("REQUESTS")
        print(request)
        first_line = request.split("\r\n")[0] # parse the first line
        url = first_line.split(" ")[1] # get url
        #url = "https://google.com:443"
        http_pos = url.find("://")
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos + 3):]
        webserver = ""
        port = -1
        port_pos = temp.find(":")
        flag = 0
        webserver_pos = temp.find("/") # find end of web server
        print("TEMP IS")
        print(temp)
        if webserver_pos == -1:
            webserver_pos = len(temp)
        if port_pos == -1 or webserver_pos < port_pos: # default port
            port = 80
            webserver = temp[:webserver_pos]
        else: # specific port
            flag = 1
            print("SPECIFIC PORT")
            # first_occurrence = temp.find('/')  # кастомный порт 
            # second_occurrence = temp.find('/', first_occurrence + 1) 
            # index = temp.find('/', second_occurrence + 1)
            if "8000" in temp[(port_pos + 1):]:    #костыль
                port = 8000
            else:
                port = int(temp[(port_pos + 1):])
            print(port)
            webserver = temp[:port_pos]
            print(webserver)
        if not flag:
            match = re.search(r'Host: \S+', request)
            print("MATCH is"+str(match))
            result = match.group(0)[6:]
            print(result)
            index = result.find(':')
            port = int(result[index+1:])
            print("PORT "  + str(port))

        write("Connected by", str(client_addr))
        write("ClientSocket", str(client_conn))
        write("Browser Request:")
        write(request)
        server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_conn.settimeout(1000)
        try:
            server_conn.connect((webserver, port)) # "server_conn" connect to public web server, like www.google.com:443.
        except: # socket.gaierror: [Errno 11001] getaddrinfo failed
            client_conn.close()
            server_conn.close()
            print("ERROR " + str(webserver) + "  port" + str(port))
            return
        if port==443:
            client_conn.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
            client_conn.setblocking(0)
            server_conn.setblocking(0)
            write("Connection established")
            # now = time.time()
            client_browser_message = b""
            website_server_message = b""
            error = ""
            print(origin_request)
            while 1:
                # if time.time()-now>1: # SET TIMEOUT
                    # server_conn.close()
                    # client_conn.close()
                    # break
                try:
                    reply = client_conn.recv(1024)
                    if not reply: break
                    server_conn.send(reply)
                    client_browser_message += reply
                except Exception as e:
                    pass
                    # error += str(e)
                try:
                    reply = server_conn.recv(1024)
                    if not reply: break
                    client_conn.send(reply)
                    website_server_message += reply
                except Exception  as e:
                    pass
            # error += str(e)
            write("Client Browser Message:")
            write(client_browser_message+b"\n")
            write("Website Server Message:")
            write(website_server_message+b"\n")
            # write("Error:")
            # write(error+"\n")
            server_conn.shutdown(socket.SHUT_RDWR)
            server_conn.close()
            client_conn.close()
            return
        print(origin_request)
        print("PORT: ", str(port))
        ####### здесь нужен код подмены куки в origin_request
        ###########
        encoded_bytes = origin_request
        decoded_string = encoded_bytes.decode('utf-8')

        print("AAAA")
        if type =='cookie':
            if 'http://127.0.0.1' in decoded_string:   #### костыль
                print("CHANGE LOCALHOST")
                creds = self.get_random_cred()
                decoded_string = encoded_bytes.decode('utf-8')
                d = decoded_string.replace("http://127.0.0.1:8000", '',1)
                #d = d.replace("sessionid=wg1x80nno4h7azp20zxztnizu1rzht3n;", 'sessionid=PA')
                if creds:
                    index1 = d.find("csrftoken")
                    old_csrf = d[index1:index1+42]
                    index1 = d.find("sessionid")
                    old_session = d[index1:index1+42]
                    print("1 OLD SESSIONS is ")
                    print(old_session)
                    print("REQ BEFORE")
                    print(d)
                    try:
                        index1 = d.find("csrfmiddlewaretoken")
                        if index1 > 1:
                            csrfmiddlewaretoken = d[index1+20:index1+84]
                            print("I CHANGE ")
                            print(csrfmiddlewaretoken)
                            #d = d.replace(csrfmiddlewaretoken, creds.get("csrf_middle_ware"))
                            print("AFTER CHANGE")
                            print(d)
                    except Exception as err:
                        pass
                    
                    print("OLD SESSION")
                    print(old_session)
                    d = d.replace(old_session, creds.get("sessionid"))
                    print(d)
                    d = d.replace(old_csrf, creds.get("csrftoken"))
                origin_request = d.encode('utf-8')

                print(origin_request)
        else: ### атха по токенам и все остальое
            if 'http://127.0.0.1' in decoded_string:   #### костыль
                
                print("CHANGE LOCALHOST")
                creds = self.get_random_tokens()
                decoded_string = encoded_bytes.decode('utf-8')
                d = decoded_string.replace("http://127.0.0.1:8000", '',1)
                fiels = creds.split(' ')
                tmp_creds = {'access':fiels[0],'refresh':fiels[1],'csrf_middle_ware':fiels[2], 'sessionid':fiels[3], 'csrftoken':fiels[4]}
                creds = tmp_creds
                if creds:
                    index1 = d.find("csrftoken")
                    old_csrf = d[index1:index1+42]
                    index1 = d.find("sessionid")
                    old_session = d[index1:index1+42]
                    access_string = d[d.find("access"):]
                    refresh_string = d[d.find("refresh"):]
                    cookie_index = d.find('Cookie:')
                    cookies = d[cookie_index+7:d.find('Connection')-2]
                    cookies = cookies.split('; ')
                    access = ''
                    refresh = ''
                    for i in cookies:
                        if i.startswith('access'):
                            access = i[len("access="):]
                        if i.startswith('refresh'):
                            refresh = i[len("refresh="):]
                    
                    try:
                        index1 = d.find("csrfmiddlewaretoken")
                        if index1 > 1:
                            csrfmiddlewaretoken = d[index1+20:index1+84]
                            print(csrfmiddlewaretoken)
                            d = d.replace(csrfmiddlewaretoken, creds.get("csrf_middle_ware"))
                    except Exception as err:
                        pass
                    
                    d = d.replace(old_session, creds.get("sessionid"))
                    d = d.replace(old_csrf, creds.get("csrftoken"))
                    d = d.replace(access, creds.get("access"))
                    d = d.replace(access, creds.get("refresh"))
                origin_request = d.encode('utf-8')

        server_conn.sendall(origin_request)
        old_session = ''
        write("Website Host Result:")
        while 1:
            # receive data from web server
            data = server_conn.recv(4096)
            try:
                write(data.decode(encoding="utf-8"))
            except:
                write(data)
            if len(data) > 0:
                client_conn.send(data)  # send to browser/client
            else:
                break
        server_conn.shutdown(socket.SHUT_RDWR)
        server_conn.close()
        client_conn.close()


base_username = "user_"
base_password = "password_" 


def get_cookies(logins, passwords,
                 url='http://127.0.0.1:8000/accounts/login/?next=main:index',
                 csrf_name='csrftoken',
                 session_name='sessionid'):

    num_users = len(logins)
    
    logins = logins.split('\r\n')
    print(logins)
    passwords = passwords.split('\r\n')
    print(passwords)
    pattern_csrftoken = r'(csrftoken=[\w]+;)'
    pattern_sessionid = r'(sessionid=[\w]+;)'
    for i in range(num_users):
        if i < len(logins)-1:
            print(i)
            username = logins[i]
            password = passwords[i]
            response = requests.get(url)
            cookies = response.headers.get('Set-Cookie')
            csrftoken = result = re.search(pattern_csrftoken, cookies)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36',
                'Cookie': csrftoken.group(1)
            }
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'username': username,
                'password': password
            }

            response = requests.post(url, headers=headers, data=data, allow_redirects=False)
        # print(response.text)
        #  print(response.headers)
            cookies = response.headers.get('Set-Cookie')
            soup = BeautifulSoup(response.text, 'html.parser')
            try:
                csrftoken = re.search(pattern_csrftoken, cookies).group(1) # нада 
            
                session_id = re.search(pattern_sessionid, cookies).group(1) # нада 
                csrf_middle_ware = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            except Exception as err:
                pass

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36',
                'Cookie': csrftoken + ' ' + session_id
            }
            response = requests.get('http://127.0.0.1:8000/accounts/login/?next=main:index', headers=headers, allow_redirects=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_middle_ware = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']


            SESSION_STORAGE.append(session_id +' ' +csrftoken+' '+ csrf_middle_ware)

def token_update(expiretime=10000, url = 'http://127.0.0.1:8000/get_token'):
    print("OLD SESSIONS IS")
    for i in range(len(SESSION_STORAGE)):
        fiels = SESSION_STORAGE[i].split(' ')
        if len(fiels)>=4:
            access=fiels[0]
            refresh=fiels[1]
            csrf_middle_ware=fiels[2]
            sessionid=fiels[3]
            
            payload = jwt.decode(refresh, SECRET_KEY, algorithms=['HS256'])
            expire = payload.get('exp')
            print(expire)
        
            if (int(time.time())+ 10000000) >= int(expire) :
                ##### код обновления токена если у нас нет ключа для подписи jwt 
                print("Обновление токена")
                cookies = {
                    'access': access,
                    'refresh': refresh,
                    'sessionid': sessionid
                }
                print('access is '+ access)
                response=requests.get(url, cookies=cookies)
                cookie = response.headers.get('Set-Cookie')
                print("COOKIE IS ")
                print(cookie)
                access = re.search('access=(.*?)(;|,)', cookie).group(1)
                refresh = re.search('refresh=(.*?)(;|,)', cookie).group(1)
                print("NEW ACCESS IS ")
                print(access)
                SESSION_STORAGE[i] = access + ' ' + refresh + ' ' + csrf_middle_ware + ' ' + sessionid

            else:
                #### ничего не делаем, он еще живет.
                pass

@app.task
def get_tokens(logins, passwords,
                 url='http://127.0.0.1:8000/accounts/login/?next=main:index',
                 csrf_name='csrftoken',
                 session_name='sessionid'):
    print("GET TOKENS")
    num_users = len(logins)
    
    logins = logins.split('\r\n')
    print(logins)
    passwords = passwords.split('\r\n')
    print(passwords)
    pattern_csrftoken = r'(csrftoken=[\w]+;)'
    pattern_sessionid = r'(sessionid=[\w]+;)'
    for i in range(num_users):
        if i < len(logins)-1:
            print(i)
            username = logins[i]
            password = passwords[i]
            response = requests.get(url)
            cookies = response.headers.get('Set-Cookie')
            print("COOKIES")
            print(cookies)
            csrftoken = result = re.search(pattern_csrftoken, cookies)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36',
                'Cookie': csrftoken.group(1)
            }
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'username': username,
                'password': password
            }

            response = requests.post(url, headers=headers, data=data, allow_redirects=False)
            cookies = response.headers.get('Set-Cookie')
            soup = BeautifulSoup(response.text, 'html.parser')
            try:
                csrftoken = re.search(pattern_csrftoken, cookies).group(1) # нада 
            
                session_id = re.search(pattern_sessionid, cookies).group(1) # нада 
                csrf_middle_ware = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            except Exception as err:
                pass

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36',
                'Cookie': csrftoken + ' ' + session_id
            }
            response = requests.get('http://127.0.0.1:8000/get_token', headers=headers, allow_redirects=False)
            cookies = response.headers.get('Set-Cookie')
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_middle_ware = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']

            print(cookies)
            access = re.search('access=(.*?)(;|,)', cookies).group(1)
            refresh = re.search('refresh=(.*?)(;|,)', cookies).group(1)
            SESSION_STORAGE.append(access + ' ' +refresh+ ' '+ csrf_middle_ware+ ' ' + session_id+ ' '+ csrftoken)



@app.task
def run_proxy(ID):
    proxy_config = ProxyConfig.objects.get(id=ID)
    print(proxy_config)
    print(proxy_config.IP)
    print(proxy_config.passwords)
    print("SESSION STORAGE IS")
    Proxy(sessions=SESSION_STORAGE)

@app.task
def run_full_scan(ID):
    scan = FullScan.objects.filter(id=ID)
    domains = scan[0].domains.split('\r\n')
    subfinder_result=[]
    assetfinder_result=[]
    amass_result = []
    subprocess.run(f" {ID}", shell=True)
    subprocess.run(f" {ID}", shell=True)
    subprocess.run(f" {ID}", shell=True)

    print("DOMAINS")

    for d in domains:
        subprocess.run(f' {d} ', shell=True)

    for d in domains:
        subprocess.run(f' {d}', shell=True)

    dedup_domains = []

    for d in subfinder_result:
        if d not in dedup_domains:
            dedup_domains.append(d)

    for d in assetfinder_result:
        if d not in dedup_domains:
            dedup_domains.append(d)

    for d in amass_result:
        if d not in dedup_domains:
            dedup_domains.append(d)
    domains_text = ''
    
    sleep(3)
    for d in dedup_domains:
        domains_text+= str(d) + '\n'
    FullScan.objects.filter(id=ID).update(domains=domains_text, status='Поиск поддоменов завершен')
    full_scan_obj=FullScan.objects.get(id=ID)
    subprocess.run(f" {ID}", shell=True)

    # КУСОК КОДА С ЗАПУСКОМ Nuclei
    subprocess.run(f" {ID}", shell=True)

    print("Домены отправленные в НУКЛЕЙ")
    print(dedup_domains)
    for d in dedup_domains:
        print('domain is ')
        print(d)
        print(type(d))
        d= d.replace("b'", '')
        nuclei_scan = NucleiScan.objects.create(status='В процессе', domain=d, full_scan=full_scan_obj)
        nuclei_instance=NucleiScan.objects.get(id=nuclei_scan.pk)
        subprocess.run(f" {d} ", shell=True)

        with open(f' {d}', 'r') as file1:
            nuclei_result = file1.readlines()
            print(len(nuclei_result))

            jsons_results = []
            for n in nuclei_result:
                jsons_results.append(json.loads(n)) 
            print("json_resulsts")
            print(len(jsons_results))
            for j_r in jsons_results:
                info = j_r.get('info', ' ')
                print("start")
                NucleiTrigger.objects.create(status = 'Не обработано',
                                                description=info.get('description', ' '),
                                                rule=j_r.get('template', ' '),
                                                severity=info.get('severity', ' '),
                                                NucleiScan=nuclei_instance,
                                                domain=d)
                print('finish')
        NucleiScan.objects.filter(id=nuclei_scan.pk).update(status='Сканирование завершено, можно посмотреть результаты')
    FullScan.objects.filter(id=ID).update(status='Сканирование Nuclei завершено, ожидается crawling')
########### CRAWLING 
    scan = FullScan.objects.filter(id=ID)
    dedup_domains = scan[0].domains.split('\n')
    full_scan_obj = FullScan.objects.get(id=ID)
    subprocess.run(f" {ID}", shell=True)
    print("Домены отправленные в КРАУЛИНГ")
    print(dedup_domains)
    for d in dedup_domains:
        d = d.replace("b'", '')
        print(d)
        crawl_scan = CrawlScan.objects.create(status='В процессе', domain=d, full_scan=full_scan_obj)
        crawl_instanse=CrawlScan.objects.get(id=crawl_scan.pk)
        subprocess.run(f"ls {d} ", shell=True)
        with open(f'ls {d}', 'r') as file1:
            crawl_resulsts = file1.readlines()
            print("json_resulsts")
            print(len(crawl_resulsts))
            #### код дедупликаци 
            clear_urls = [] 
            for url in crawl_resulsts:
                if not black_list_extensions(url) and url not in clear_urls:
                    clear_urls.append(url)
            domains = split_by_domains(clear_urls)
            new_urls = []
            for domain in domains.keys():
                new_urls+=domains[domain]
            for domain in domains.keys():
                domains[domain] = delete_simple_pages(domains[domain])
            dedup_hars = []
            for domain in domains.keys():
                dedup_hars+=domains[domain]
            for j_r in dedup_hars:
                Har.objects.create(har=j_r,
                                   CrawlScan=crawl_instanse,
                                   domain=d,
                                   type='Пасивный')
        CrawlScan.objects.filter(id=crawl_scan.pk).update(status='Пасивное сканирование завершено')
    FullScan.objects.filter(id=ID).update(status='Пасивный сбор HAR завершен')

############ запуск KATANA
    subprocess.run(f" {ID}", shell=True)
    for d in dedup_domains:
        d = d.replace("b'", '')
        print(d)
        crawl_scan = CrawlScan.objects.filter( domain=d, full_scan=ID)
        print(crawl_scan)
        print("ID")
        print(crawl_scan[0].id)
        crawl_instanse=CrawlScan.objects.get(id=crawl_scan[0].id)

        subprocess.run(f"ls {d}", shell=True) ### заменить ct на 1800
        with open(f'./katana/{ID}/{d}', 'r') as file1:
            active_crawl_resulsts = file1.readlines()
            jsons_results = []
            for n in active_crawl_resulsts:
                jsons_results.append(json.loads(n))
            for j_r in jsons_results:
                raw = j_r.get('request').get('endpoint') ## если что заменить на raw
                print("raw is ")
                print(raw)
                Har.objects.create(har=raw,
                    CrawlScan=crawl_instanse,
                    domain=d,
                    type='Активный')
        CrawlScan.objects.filter(id=crawl_scan[0].id).update(status='Активное сканирование завершено')
    FullScan.objects.filter(id=ID).update(status='Активный сбор HAR завершен')
    print("CRAWLING ЗАКОНЧЕН")
    run_zap(ID)
################ ZAP
    crawl_scan = CrawlScan.objects.filter(full_scan=ID)
    print(crawl_scan)
    for i in range(len(crawl_scan)):
        hars = Har.objects.filter(CrawlScan=crawl_scan[i].id)
        print(len(hars))
        print("ЗАПУСК ЗАПА")
        print(hars)
        full_scan_instanse=FullScan.objects.get(id=ID)
        subprocess.run(f'ls {ID}', shell=True)
        try:
            for har in hars:
                zp_scan=ZapScan.objects.create(full_scan=full_scan_instanse, har_id=hars[0], status = 'Новый') ## убрать отсюда индекс
                zap_instanse=ZapScan.objects.get(id=zp_scan.pk)
                print(har.har)
                HAR = har.har
                HAR = HAR.replace('\n','')
                pwd = os.getcwd()
                print(pwd)
                subprocess.run(f" ls {ID}", shell=True)
                with open(f'./ZAP/{ID}/{har.id}.json', 'r') as fcc_file:
                    fcc_data = json.load(fcc_file)
                    if fcc_data.get('site'):
                        alerts=fcc_data.get('site')[0].get('alerts', [])
                    else:
                        alerts = [] 
                    print(len(alerts))
                    for alert in alerts:
                        ZapTrigger.objects.create(Zap_scan=zap_instanse,
                                                har_id=har,
                                                riskdesc=alert['riskdesc'],
                                                instance_metod=alert['instances'][0].get('method', ' '),
                                                instance_url=alert['instances'][0].get('uri', ' '),
                                                instance_param=alert['instances'][0].get('param', ' '),
                                                instance_attack=alert['instances'][0].get('attack', ' '),
                                                instance_evidence=alert['instances'][0].get('evidence', ' '),
                                                instance_otherinfo=alert['instances'][0].get('otherinfo', ' '),
                                                status = 'Не обработано')
                    ZapScan.objects.filter(id=zp_scan.pk).update(status='Сканирование завершено, можно посмотреть результаты')
                    Har.objects.filter(id=har.id).update(status ='Сканирование ZAP завершено, можно посмотреть результаты')
            FullScan.objects.filter(id=ID).update(status='Сканирование полностью завершено')
        except Exception as err:
            print(err)

@app.task
def run_crawl(ID):
    scan = FullScan.objects.filter(id=ID)
    dedup_domains = scan[0].domains.split('\n')
    full_scan_obj = FullScan.objects.get(id=ID)
    subprocess.run(f"ls {ID}", shell=True)
    print("Домены отправленные в КРАУЛИНГ")
    print(dedup_domains)
    for d in dedup_domains:
        d = d.replace("b'", '')
        print(d)
        crawl_scan = CrawlScan.objects.create(status='В процессе', domain=d, full_scan=full_scan_obj)
        crawl_instanse=CrawlScan.objects.get(id=crawl_scan.pk)
        subprocess.run(f"ls ", shell=True)
        with open(f'./xurlfinder/{ID}/{d}', 'r') as file1:
            crawl_resulsts = file1.readlines()
            print("json_resulsts")
            print(len(crawl_resulsts))
            #### код дедупликаци 
            clear_urls = [] 
            for url in crawl_resulsts:
                if not black_list_extensions(url) and url not in clear_urls:
                    clear_urls.append(url)
            domains = split_by_domains(clear_urls)
            new_urls = []
            for domain in domains.keys():
                new_urls+=domains[domain]
            for domain in domains.keys():
                domains[domain] = delete_simple_pages(domains[domain])
            dedup_hars = []
            for domain in domains.keys():
                dedup_hars+=domains[domain]
            for j_r in dedup_hars:
                Har.objects.create(har=j_r,
                                   CrawlScan=crawl_instanse,
                                   domain=d,
                                   type='Пасивный')
        CrawlScan.objects.filter(id=crawl_scan.pk).update(status='Пасивное сканирование завершено')
    FullScan.objects.filter(id=ID).update(status='Пасивный сбор HAR завершен')

    # запуск katana
    subprocess.run(f"ls {ID}", shell=True)
    for d in dedup_domains:
        d = d.replace("b'", '')
        print(d)
        crawl_scan = CrawlScan.objects.filter( domain=d, full_scan=ID)
        print(crawl_scan)
        print("ID")
        print(crawl_scan[0].id)
        crawl_instanse=CrawlScan.objects.get(id=crawl_scan[0].id)

        with open(f'./katana/{ID}/{d}', 'r') as file1:
            active_crawl_resulsts = file1.readlines()
            jsons_results = []
            for n in active_crawl_resulsts:
                jsons_results.append(json.loads(n))
            for j_r in jsons_results:
                raw = j_r.get('request').get('endpoint') ## если что заменить на raw
                print("raw is ")
                print(raw)
                Har.objects.create(har=raw,
                    CrawlScan=crawl_instanse,
                    domain=d,
                    type='Активный')
        CrawlScan.objects.filter(id=crawl_scan[0].id).update(status='Активное сканирование завершено')
    FullScan.objects.filter(id=ID).update(status='Активный сбор HAR завершен')



@app.task
def run_zap(ID):
    crawl_scan = CrawlScan.objects.filter(full_scan=ID)
    print(crawl_scan)
    for i in range(len(crawl_scan)):
        hars = Har.objects.filter(CrawlScan=crawl_scan[i].id)
        print(len(hars))
        print("ЗАПУСК ЗАПА")
        print(hars)
        full_scan_instanse=FullScan.objects.get(id=ID)
        try:
            for har in hars:
                zp_scan=ZapScan.objects.create(full_scan=full_scan_instanse, har_id=hars[0], status = 'Новый') ## убрать отсюда индекс
                zap_instanse=ZapScan.objects.get(id=zp_scan.pk)
                print(har.har)
                HAR = har.har
                HAR = HAR.replace('\n','')
                pwd = os.getcwd()
                print(pwd)
                with open(f'./ZAP/{ID}/{har.id}.json', 'r') as fcc_file:
                    fcc_data = json.load(fcc_file)
                    if fcc_data.get('site'):
                        alerts=fcc_data.get('site')[0].get('alerts', [])
                    else:
                        alerts = [] 
                    print(len(alerts))
                    for alert in alerts:
                        ZapTrigger.objects.create(Zap_scan=zap_instanse,
                                                har_id=har,
                                                riskdesc=alert['riskdesc'],
                                                instance_metod=alert['instances'][0].get('method', ' '),
                                                instance_url=alert['instances'][0].get('uri', ' '),
                                                instance_param=alert['instances'][0].get('param', ' '),
                                                instance_attack=alert['instances'][0].get('attack', ' '),
                                                instance_evidence=alert['instances'][0].get('evidence', ' '),
                                                instance_otherinfo=alert['instances'][0].get('otherinfo', ' '),
                                                status = 'Не обработано')
                    ZapScan.objects.filter(id=zp_scan.pk).update(status='Сканирование завершено, можно посмотреть результаты')
                    Har.objects.filter(id=har.id).update(status ='Сканирование ZAP завершено, можно посмотреть результаты')
            FullScan.objects.filter(id=ID).update(status='Сканирование полностью завершено')
        except Exception as err:
            print(err)

def black_list_extensions(url):
    for extension in BLACK_LIST:
        if extension in url:
            return True
    return False 


def split_by_domains(urls):
    domains = {}
    for url in urls:
        host = urlparse(url).hostname
        if host not in domains.keys():
            domains[host] = []
        else:
            domains[host].append(url)
    return domains


def end_with_digits(url):
    if url.endswith("/"):
        url = url[:-1]
    index = url.rfind('/')
    last_path = url[index+1:]
    try:
        a = int(last_path)
        return True
    except:
        return False
    

def delete_simple_pages(urls):
    copy_urls = []
    need_delete = []
    i = 0 
    for url in urls:
        i+=1
        print(i)
        if end_with_digits(url):
            copy_urls.append(url)
            path = get_path_without_last(url)
            for URL in urls:
                if get_path_without_last(URL) == path:
                    need_delete.append(URL)
    result_urls = []
    for url in urls:
        if url not in need_delete:
            result_urls.append(url)
    for url in copy_urls:
        if url not in result_urls:
            result_urls.append(url)
    return result_urls


def get_path_without_last(url):
    url = url.replace('//', '')
    start = url.find('/')
    last = url.rfind('/')
    last_path = url[start:last]
    return last_path


def zap_deduplicate(zap_triggers):
    for zap_trigger in zap_triggers:
        pass
    dedupliceted_triggers = deduplicate_sign(zap_triggers)
    return dedupliceted_triggers

def deduplicate_sign(zap_triggers):
    signs = []
    dedup_triggers = []
    for zap_trigger in zap_triggers:
        sign = str(zap_trigger.instance_evidence)+str(zap_trigger.instance_url)
        if sign not in signs:
            signs.append(sign)
    for zap_trigger in zap_triggers:
        if str(zap_trigger.instance_evidence)+str(zap_trigger.instance_url) in signs:
            dedup_triggers.append(zap_trigger)
            signs.remove(str(zap_trigger.instance_evidence)+str(zap_trigger.instance_url))
    return dedup_triggers
