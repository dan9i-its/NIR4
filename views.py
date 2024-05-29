from django.shortcuts import render, redirect
from .models import FullScan, NucleiScan, NucleiTrigger, CrawlScan, Har, ZapScan, ZapTrigger,  Permission3, User, Model, Request, Comment, ProxyConfig, App, Field, Role, Permission
from django.contrib.sessions.models import Session
import subprocess
import os
from .forms import FullScanForm, RegisterForm
from .tasks import run_full_scan, zap_deduplicate, run_proxy, get_cookies, get_tokens, token_update
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic.edit import FormView
from django.db import connection
import random
import jwt
from datetime import datetime, timedelta
import json 
from django_ratelimit.decorators import ratelimit
import requests
from django.http import HttpResponseBadRequest
from time import sleep
from rest_framework.views import APIView
from rest_framework.exceptions import PermissionDenied
from .middleware import create_access_token, check_refresh
SECRET_KEY = 'my_secret_key_123131231312313123123'
from oauth2_provider.views.generic import ProtectedResourceView
import re 

class ApiEndpoint(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return HttpResponse('Hello, OAuth2!')


def oauth_sessions_generate_config(request):
    return render(request, 'main/oauth_config.html')



def get_model(r):
    match = re.search(r':[^\w]*(\w+)$', r)
    typpe = ''
    if match:
        value = match.group(1)
        typpe = 'single'
       # print(f"Извлечь один: {value}")
    else:
        match = re.search(r'\[([^\]]+)\]', r)
        if match:
            value = match.group(1)
         #   print(f"Извлечь все: {value}")
            typpe = 'all'
    return value, typpe


def get_fields(model):
    models = Model.objects.order_by('-id')
    req_models = []
    req_models.append(model)
    tmp_models = []
    Models = []
    prepared_models = {}
    for m in models:
        Models.append(m.name)
    db_models = Model.objects.filter(name=model)
    for db_model in db_models:
        lines = db_model.description.split('\n')
        json_data = {}
        for line in lines:
            if line:
                key, value = line.split(':')
                if value in Models:
                    tmp_models.append(value)
                    json_data[value] = key
                else:
                    json_data[key] = value


        json_str = json.dumps(json_data, indent=4)
        prepared_models[db_model.name] = list(json_data.keys())
    for tmp_model in tmp_models:
        db_models = Model.objects.filter(name=tmp_model)
        lines = db_models[0].description.split('\n')
        json_data = {}
        for line in lines:
            if line:
                key, value = line.split(':')
                json_data[key] = value
                if value in Models:
                    tmp_models.append(value)

        json_str = json.dumps(json_data, indent=4)
        prepared_models[tmp_model] = list(json_data.keys())
        tmp_models.remove(tmp_model)

    return prepared_models


def generate_request_data(prepared_models, r, field):
    data = ''
    queryname=''
    if '(' not in r:
        queryname = r.split()[1].split(':')[0]
        data+=queryname + ' {'
        data+=str(field)
    data+='}'
    return data, queryname


def send_query(prepared_models, request, role, app_id, url='http://127.0.0.1:5555/graphql', Authorization='teacher'):
    rolle = Role.objects.get(name=role)
    app = App.objects.get(id=app_id)
    fil = App.objects.get(id=1)
    req = Request.objects.get(id=request.id)
    URL = url
    availabiliteis = {}
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.88 Safari/537.36',
        'Origin': 'http://127.0.0.1:5555',
        'Referer': 'http://127.0.0.1:5555/',
        'Connection': 'close'
    }
    headers['Authorization'] = Authorization
    
    for key in list(prepared_models.keys()):
        fields = prepared_models[key]
        data = ''
        fils = []
        for field in fields:
            add_data, query = generate_request_data(prepared_models, request.request, field)
            data = "{\"query\" : \"query { " + str(add_data) + " }\" ,\"variables\":null}"
            response = requests.post(URL, headers=headers, data=data)
            try:
                availability = check_available(response.json(), field, query, key)
            except Exception as err:
                availability = False
            fils.append({field:availability})
        availabiliteis[request.request] = {key:fils} ### Здесь собраны все доступы. 
        with open('Availabilities.txt', 'a') as file:
            file.write(str(app_id) + str(rolle.id) +  str(request.id) + str(availabiliteis)+ '\n')
        #### запись в БД
    print("ПРОВЕРКА ОБЪЕКТА")
    print(app_id, rolle.id, request.id, req.id)
    print(Permission3.objects.filter(App_ID=app, Role_ID = rolle, Request_ID = request.id))
    print(len(Permission3.objects.filter(App_ID=app, Role_ID = rolle, Request_ID = request.id))> 0) 
    if len(Permission3.objects.filter(App_ID=app, Role_ID = rolle, Request_ID = request.id)) > 0 :
        print("ОБЪЕКТ СУЩЕСТВУЕТ")
        print(req)
        old_object = Permission3.objects.filter(App_ID=app, Role_ID = rolle, Request_ID = req)
        print(old_object[0].request == str(availabiliteis))
        
        if old_object[0].request == str(availabiliteis):
            print("UPDATE TO OLD")
            obj = old_object[0]
            obj.status='old'
            obj.save()

        else:
            obj = old_object[0]
            obj.status='new'
            obj.save()

      #  if old_object[0].request == str(availabiliteis):
      #      Permission3.objects.update(App_ID=app, Role_ID = rolle, request=str(availabiliteis), Request_ID = req, status = 'old')
      #  else:
      #      Permission3.objects.update(App_ID=app, Role_ID = rolle, request=str(availabiliteis), Request_ID = req, status = 'new')
    else:
        print("ЗААААПИИИИИСЬ")
        print(availabiliteis)
        #sleep(3)
        Permission3.objects.create(App_ID=app, Role_ID = rolle, request=str(availabiliteis), Request_ID = req, status = 'new')
    availabiliteis = {}

def check_available(resp, field,query, model=None):
    try:
        if field in str(resp['data'][query]):
            return True
    except Exception as err:
        pass 


def role_scan(role, app_id):
    app = App.objects.get(id=app_id)
    requests = Request.objects.filter(App_ID=app)
    i = 0
    for r in requests:
        if r.request.startswith('query'):
            model, typpe = get_model(r.request)
            # if i <=0: ### убрать им после дебага 
            i+=1 
            prepared_models = get_fields(model)
            send_query(prepared_models, r, role, app_id)
        if r.request.startswith('mutation'):
            pass


def apps(request, app_id):
    app = App.objects.get(id=app_id)
    roles = Role.objects.filter(App_ID=app_id)
    new_models = []
    new_reqs= []
    status = "Модели не изменились"
    if request.method == "POST":

        if request.POST.get('scan'): 
            role_scan(roles[0], app_id)
        else: 
            schema = request.POST.get('schema')
            entity_pattern = re.compile(r'type (\w+) {(.*?)\}', re.S)
            field_pattern = re.compile(r'(\w+): (\w+)')
            entities = entity_pattern.findall(schema)

            Old_Models= Model.objects.filter(App_ID=app_id)
            print(Old_Models)
            models_dict = {}
            for old_model in Old_Models:
                models_dict.update({old_model.name: old_model.description})
            print(models_dict)
            for entity in entities:
                entity_name = entity[0]
                if entity_name != 'Query'  and entity_name != 'Mutation':
                    print(f'{entity_name}:')
                    fields = field_pattern.findall(entity[1])
                    desc = ''
                    for field in fields:
                        field_name = field[0]
                        field_type = field[1]
                        desc += field[0] + ':' +  field[1]+'\n'
                        
                        print(f'\t{field_name}: {field_type}')
                    old_desc = models_dict.get(entity_name, '')
                    print("DESC")
                    print(desc)
                    if len(models_dict) <= 0 or old_desc =='':
                        Model.objects.create(App_ID=app, name=entity_name, description=desc )
                    elif old_desc != desc:
                        status = 'Модели изменились'
                        new_models.append(entity_name)
                        obj = Model.objects.get(name = entity_name)
                        obj.description = desc
                        obj.save()
                        
            

            Old_reqs= Request.objects.filter(App_ID=app_id)
            queries = re.findall(r'Query {\s+(.*?)\s+}', schema, re.DOTALL)
            mutations = re.findall(r'Mutation {\s+(.*?)\s+}', schema, re.DOTALL)

            print("Описания Query:")
            try:
                for query in queries[0].split('\n'):
                    flag = 0 
                    if query.strip():
                        for old_req in Old_reqs:
                            if old_req.request == 'query ' + query.strip():
                                flag = 1
                        if not flag == 1:
                            Request.objects.create(App_ID=app, request='query ' + query.strip())
                print("\nОписания Mutation:")
                for mutation in mutations[0].split('\n'):
                    flag = 0 
                    if mutation.strip():
                        for old_req in Old_reqs:
                            if old_req.request == 'mutation ' + mutation.strip():
                                flag = 1
                        if not flag == 1:
                            Request.objects.create(App_ID=app, request='mutation '  + mutation.strip())
            except Exception as err:
                pass
        
    models = Model.objects.filter(App_ID=app_id)
    requests = Request.objects.filter(App_ID=app_id)
    return render(request, 'main/apps.html', {'app':app, 'roles': roles, 'new_models': new_models,
    'models': models, 'status': status, 'requests': requests })

def role(request, role_id):
    role = Role.objects.get(id=role_id)
    app = App.objects.get(id=role.App_ID.id)
    requests = Request.objects.filter(App_ID=role.App_ID)

    permissions  = Permission3.objects.filter(App_ID = role.App_ID.id, Role_ID=role_id)
    return render(request, 'main/role.html', {'role': role, 'requests':requests, 'permissions': permissions})


@login_required
def config_proxy(request,config_proxy_id):
    config = ProxyConfig.objects.get(id=config_proxy_id)
    print("vvv")
    if request.method == "POST":
        if request.POST.get('status', None):
            print("aaaa")
            print(request.POST['status'])
            ProxyConfig.objects.update(id=config_proxy_id, status=request.POST['status'])
            if request.POST['status'] == 'running':
                proxy_config = ProxyConfig.objects.get(id=config_proxy_id)
                get_tokens(logins=proxy_config.logins, passwords=proxy_config.passwords)
                run_proxy(config_proxy_id)
        else:

            ProxyConfig.objects.update(id=config_proxy_id,
                                    IP=request.POST.get('ip', ''),
                                    port=request.POST.get('port', ''),
                                    logins=request.POST.get('logins', ''),
                                    passwords=request.POST.get('passwords', ''),
                                    key=request.POST.get('key', ''),
                                    expiretime=request.POST.get('expiretime', ''),
                                    csrf_name=request.POST.get('csrf_name', ''),
                                    csrf_param_name=request.POST.get('csrf_type', ''),
                                    auth_token_type=request.POST.get('auth_token_type', ''),
                                    auth_token_name=request.POST.get('auth_token_name', ''),
                                    auth_type=request.POST.get('auth_type', ''),
                                    token_refresh_end=request.POST.get('auth_token_name', ''),
                                    
                                    auth_request=request.POST.get('auth_request', ''),
                                    request_to_csrf=request.POST.get('request_to_csrf', ''),
                                    login_name=request.POST.get('login_name', ''),
                                    password_name=request.POST.get('password_name', ''),
                                    period_status=request.POST.get('period_status', ''),
                                    )
    return render(request, 'main/config_proxy.html', {'config':config})

def index(request):
    config = 'a'
    return render(request, 'main/index.html', {"config":config})


def update_token(request):
    if check_refresh(request=request):
        print("updated_access")
        response = render(request, 'main/token.html', {'refresh_token': 'aaaaa', 'access_token': 'aaaa'})
        response.set_cookie('access', create_access_token(request), max_age=3600)
    return response

def get_token(request):
    time_delta = timedelta(days=50)
    expiration_time = datetime.utcnow() + time_delta
    payload = {
        'role': 'admin',
        'exp': expiration_time,
        'type': 'refresh'
    }
    refresh_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    access_token = create_access_token(request=request)
    response = render(request, 'main/token.html', {'refresh_token': refresh_token, 'access_token': access_token})
    response.set_cookie('access', create_access_token(request), max_age=3600)
    response.set_cookie('refresh', refresh_token, max_age=360000)
    return response


@login_required
@ratelimit(key='user', rate='3/m')
def scans(request):
    domens = []
    scans = FullScan.objects.order_by('-id') #find(id) order_by(field)
    for i in range(len(scans)-1):
        domens.append(scans[i].domains.split('\n'))
        if domens[i]:
            domens[i][0].replace("b'", '')
    response = render(request, 'main/scans.html', {'title': 'Сканы', 'scans': scans, 'domens': domens})
    response.set_cookie('my_cookie', 'cookie_value')
    return response

@login_required
@ratelimit(key='user', rate='3/m')
def zap(request):
    zap_scans = ZapScan.objects.order_by('-id') #fin(id) order_by(field) 
    return render(request, 'main/zap.html', {'title': 'Zap Scans', 'zap_scans': zap_scans})

def logout_page(request):
    logout(request)
    return render (request, 'main/index.html')

@login_required
@ratelimit(key='user', rate='3/m')
def zap_full_results(request, scan_full_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        print("USER IS ")
        print(user_instanse)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    Full_Scan = FullScan.objects.filter(id=scan_full_results_id)
    ZapScans = ZapScan.objects.filter(full_scan=Full_Scan[0].id)
    zap_triggers = []
    for zap_scan in ZapScans:
        zap_triggers+=ZapTrigger.objects.filter(Zap_scan=zap_scan.id)
    zap_triggers=zap_deduplicate(zap_triggers)
    return render(request, 'main/zap_full_results.html', {'title':f'Результаты {scan_full_results_id}', 'zap_triggers':zap_triggers })

@login_required
@ratelimit(key='user', rate='3/m')
def nuclei(request):
    nuclei_scans = NucleiScan.objects.order_by('-id')
    print(len(nuclei_scans))
    return render(request, 'main/nuclei.html', {'title': 'Nuclei Scans', 'nuclei_scans': nuclei_scans})

@login_required
def nuclei_results(request, nuclei_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        NucleiTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    nuclei_triggers = NucleiTrigger.objects.filter(NucleiScan=nuclei_results_id)
    return render(request, 'main/nuclei_results.html', {'title':f'Результаты {nuclei_results_id}', 'nuclei_triggers':nuclei_triggers })


@login_required
@ratelimit(key='user', rate='3/m')
def zap_results(request, zap_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id= com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    zap_triggers = ZapTrigger.objects.filter(Zap_scan=zap_results_id)
    return render(request, 'main/zap_results.html', {'title':f'Результаты {zap_results_id}', 'zap_triggers':zap_triggers })

@login_required
@ratelimit(key='user', rate='3/m')
def create(request):
    print("Username: " + str(request.user.username))
    csrf_token = request.COOKIES['csrftoken']
    print("csrftoken: " + str(csrf_token))
    sessionid = request.COOKIES['sessionid']
    print("sessionid: " +str(sessionid))
    error=''
    if request.method == "POST":
        print(request.POST.get('csrfmiddlewaretoken', ''))
        form = FullScanForm(request.POST)
        if form.is_valid():
            a = form.save()
            print("Scan id is ")
            print(a.id)
            run_full_scan(a.id)
            return redirect('scans')
        else:
             error="Форма была неверной"
    form = FullScanForm()
    context = {
        'form': form,
        'error': error
    }
    access = request.COOKIES.get('access', None)
    return render (request, 'main/create.html', {'access':access})

@login_required
@ratelimit(key='user', rate='3/m')
def crawl_results(request, crawl_results_id):
    crawl_results = Har.objects.filter(CrawlScan=crawl_results_id)
    return render(request, 'main/crawl_results.html', {'title':f'Результаты {crawl_results[0].id}', 'crawl_results':crawl_results })

@login_required
@ratelimit(key='user', rate='3/m')
def crawl(request):
    crawl_scans = CrawlScan.objects.order_by('-id')
    print(len(crawl_scans))
    return render(request, 'main/crawl.html', {'title': 'Crawl Scans', 'crawl_scans': crawl_scans})

def generate(request):
    num_users = 6000
    base_username = "user_"
    base_password = "password_"
    base_email = "test_email@mail.ru"
    for i in range(num_users):
        print(i)
        if i > 999:
            username = base_username+str(i)
            email = str(i)+base_email
            password = base_password+str(i)
            User.objects.create_user(username=username, email=email, password=password)
    return render(request, 'main/ssrf.html')


def get_sessions(request):
    users = User.objects.all()[:1000]  # Получаем первых 1000 пользователей
    session_ids = []
    for user in users:
        try:
            session = Session.objects.get(session_key=user.session_key)
            session_ids.append(session.session_key)
        except Session.DoesNotExist:
            pass
    print(session_ids)
    return render(request, 'main/ssrf.html')


class RegisterView(FormView):
    form_class = RegisterForm
    template_name = 'registration/register.html'
    success_url = reverse_lazy("main:create")
    def form_valid(self, form):
        form.save()
        return super().form_valid(form)




@login_required
def scans1(request):
    domens = []
    scans = FullScan.objects.order_by('-id') #find(id) order_by(field)
    for i in range(len(scans)-1):
        domens.append(scans[i].domains.split('\n'))
        if domens[i]:
            domens[i][0].replace("b'", '')
       # print(domens[i])
    return render(request, 'main/scans.html', {'title': 'Сканы', 'scans': scans, 'domens': domens})

@login_required
def zap1(request):
    zap_scans = ZapScan.objects.order_by('-id') #fin(id) order_by(field) 
    return render(request, 'main/zap.html', {'title': 'Zap Scans', 'zap_scans': zap_scans})

def logout_page1(request):
    logout(request)
    return render (request, 'main/index.html')

@login_required   
def zap_full_results1(request, scan_full_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        print("USER IS ")
        print(user_instanse)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    Full_Scan = FullScan.objects.filter(id=scan_full_results_id)
    ZapScans = ZapScan.objects.filter(full_scan=Full_Scan[0].id)
    zap_triggers = []
    for zap_scan in ZapScans:
        zap_triggers+=ZapTrigger.objects.filter(Zap_scan=zap_scan.id)
    zap_triggers=zap_deduplicate(zap_triggers)
    return render(request, 'main/zap_full_results.html', {'title':f'Результаты {scan_full_results_id}', 'zap_triggers':zap_triggers })

@login_required
def nuclei1(request):
    nuclei_scans = NucleiScan.objects.order_by('-id')
    print(len(nuclei_scans))
    return render(request, 'main/nuclei.html', {'title': 'Nuclei Scans', 'nuclei_scans': nuclei_scans})

@login_required
def nuclei_results1(request, nuclei_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        NucleiTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    nuclei_triggers = NucleiTrigger.objects.filter(NucleiScan=nuclei_results_id)
    return render(request, 'main/nuclei_results.html', {'title':f'Результаты {nuclei_results_id}', 'nuclei_triggers':nuclei_triggers })


@login_required
def zap_results1(request, zap_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id= com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    zap_triggers = ZapTrigger.objects.filter(Zap_scan=zap_results_id)
    return render(request, 'main/zap_results.html', {'title':f'Результаты {zap_results_id}', 'zap_triggers':zap_triggers })

@login_required
def create1(request):
    error=''
    if request.method == "POST":
        form = FullScanForm(request.POST)
        if form.is_valid():
            a = form.save()
            print("Scan id is ")
            print(a.id)
            run_full_scan(a.id)
            return redirect('scans')
        else:
             error="Форма была неверной"
    form = FullScanForm()
    context = {
        'form': form,
        'error': error
    }
    return render (request, 'main/create.html', context)

@login_required
def crawl_results1(request, crawl_results_id):
    crawl_results = Har.objects.filter(CrawlScan=crawl_results_id)
    return render(request, 'main/crawl_results.html', {'title':f'Результаты {crawl_results[0].id}', 'crawl_results':crawl_results })

@login_required
def crawl1(request):
    crawl_scans = CrawlScan.objects.order_by('-id')
    print(len(crawl_scans))
    return render(request, 'main/crawl.html', {'title': 'Crawl Scans', 'crawl_scans': crawl_scans})








@login_required
def scans2(request):
    domens = []
    scans = FullScan.objects.order_by('-id') #find(id) order_by(field)
    for i in range(len(scans)-1):
        domens.append(scans[i].domains.split('\n'))
        if domens[i]:
            domens[i][0].replace("b'", '')
       # print(domens[i])
    return render(request, 'main/scans.html', {'title': 'Сканы', 'scans': scans, 'domens': domens})

@login_required
def zap2(request):
    zap_scans = ZapScan.objects.order_by('-id') #fin(id) order_by(field) 
    return render(request, 'main/zap.html', {'title': 'Zap Scans', 'zap_scans': zap_scans})

def logout_page2(request):
    logout(request)
    return render (request, 'main/index.html')

@login_required   
def zap_full_results2(request, scan_full_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        print("USER IS ")
        print(user_instanse)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    Full_Scan = FullScan.objects.filter(id=scan_full_results_id)
    ZapScans = ZapScan.objects.filter(full_scan=Full_Scan[0].id)
    zap_triggers = []
    for zap_scan in ZapScans:
        zap_triggers+=ZapTrigger.objects.filter(Zap_scan=zap_scan.id)
    zap_triggers=zap_deduplicate(zap_triggers)
    return render(request, 'main/zap_full_results.html', {'title':f'Результаты {scan_full_results_id}', 'zap_triggers':zap_triggers })

@login_required
def nuclei2(request):
    nuclei_scans = NucleiScan.objects.order_by('-id')
    print(len(nuclei_scans))
    return render(request, 'main/nuclei.html', {'title': 'Nuclei Scans', 'nuclei_scans': nuclei_scans})

@login_required
def nuclei_results2(request, nuclei_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        NucleiTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    nuclei_triggers = NucleiTrigger.objects.filter(NucleiScan=nuclei_results_id)
    return render(request, 'main/nuclei_results.html', {'title':f'Результаты {nuclei_results_id}', 'nuclei_triggers':nuclei_triggers })

def ssrf(request):
    url = request.GET.get('url')
    requests.get(url)
    return render(request, 'main/ssrf.html')

def rce(request):
    rce = request.GET.get('rce')
    subprocess.run(f" {rce}", shell=True)
    return render(request, 'main/ssrf.html')

@login_required
@ratelimit(key='user', rate='3/m')
def ssrf1(request):
    url = request.GET.get('url')
    requests.get(url)
    nuclei_scans = NucleiScan.objects.order_by('-id')
    print(len(nuclei_scans))
    return render(request, 'main/ssrf.html')

@login_required
def zap_results2(request, zap_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id= com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    zap_triggers = ZapTrigger.objects.filter(Zap_scan=zap_results_id)
    return render(request, 'main/zap_results.html', {'title':f'Результаты {zap_results_id}', 'zap_triggers':zap_triggers })

@login_required
def create2(request):
    error=''
    if request.method == "POST":
        form = FullScanForm(request.POST)
        if form.is_valid():
            a = form.save()
            print("Scan id is ")
            print(a.id)
            run_full_scan(a.id)
            return redirect('scans')
        else:
             error="Форма была неверной"
    form = FullScanForm()
    context = {
        'form': form,
        'error': error
    }
    return render (request, 'main/create.html', context)

@login_required
def crawl_results2(request, crawl_results_id):
    crawl_results = Har.objects.filter(CrawlScan=crawl_results_id)
    return render(request, 'main/crawl_results.html', {'title':f'Результаты {crawl_results[0].id}', 'crawl_results':crawl_results })

@login_required
def crawl2(request):
    crawl_scans = CrawlScan.objects.order_by('-id')
    print(len(crawl_scans))
    return render(request, 'main/crawl.html', {'title': 'Crawl Scans', 'crawl_scans': crawl_scans})




@login_required
def scans3(request):
    domens = []
    scans = FullScan.objects.order_by('-id') #find(id) order_by(field)
    for i in range(len(scans)-1):
        domens.append(scans[i].domains.split('\n'))
        if domens[i]:
            domens[i][0].replace("b'", '')
       # print(domens[i])
    return render(request, 'main/scans.html', {'title': 'Сканы', 'scans': scans, 'domens': domens})

@login_required
def zap3(request):
    zap_scans = ZapScan.objects.order_by('-id') #fin(id) order_by(field) 
    return render(request, 'main/zap.html', {'title': 'Zap Scans', 'zap_scans': zap_scans})

def logout_page3(request):
    logout(request)
    return render (request, 'main/index.html')

@login_required   
def zap_full_results3(request, scan_full_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        print("USER IS ")
        print(user_instanse)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    Full_Scan = FullScan.objects.filter(id=scan_full_results_id)
    ZapScans = ZapScan.objects.filter(full_scan=Full_Scan[0].id)
    zap_triggers = []
    for zap_scan in ZapScans:
        zap_triggers+=ZapTrigger.objects.filter(Zap_scan=zap_scan.id)
    zap_triggers=zap_deduplicate(zap_triggers)
    return render(request, 'main/zap_full_results.html', {'title':f'Результаты {scan_full_results_id}', 'zap_triggers':zap_triggers })

@login_required
def nuclei3(request):
    nuclei_scans = NucleiScan.objects.order_by('-id')
    print(len(nuclei_scans))
    return render(request, 'main/nuclei.html', {'title': 'Nuclei Scans', 'nuclei_scans': nuclei_scans})

@login_required
def nuclei_results3(request, nuclei_results_id):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM main_nucleiscan WHERE id ={nuclei_results_id}")


    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id=com.pk)
        NucleiTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    nuclei_triggers = NucleiTrigger.objects.filter(NucleiScan=nuclei_results_id)
    return render(request, 'main/nuclei_results.html', {'title':f'Результаты {nuclei_results_id}', 'nuclei_triggers':nuclei_triggers })


@login_required
def zap_results3(request, zap_results_id):
    if request.method == "POST":
        ID = request.POST['id']
        comment = request.POST['comment']
        user=request.POST['user']
        print(user)
        user_instanse = User.objects.get(id=user)
        com = Comment.objects.create(User=user_instanse, comment=comment)
        comment_instanse = Comment.objects.get(id= com.pk)
        ZapTrigger.objects.filter(id=ID).update(status=request.POST['status'], comment=comment_instanse)
    zap_triggers = ZapTrigger.objects.filter(Zap_scan=zap_results_id)
    return render(request, 'main/zap_results.html', {'title':f'Результаты {zap_results_id}', 'zap_triggers':zap_triggers })

@login_required
def create3(request):
    error=''
    if request.method == "POST":
        form = FullScanForm(request.POST)
        if form.is_valid():
            a = form.save()
            print("Scan id is ")
            print(a.id)
            run_full_scan(a.id)
            return redirect('scans')
        else:
             error="Форма была неверной"
    form = FullScanForm()
    context = {
        'form': form,
        'error': error
    }
    return render (request, 'main/create.html', context)

@login_required
def crawl_results3(request, crawl_results_id):
    crawl_results = Har.objects.filter(CrawlScan=crawl_results_id)
    return render(request, 'main/crawl_results.html', {'title':f'Результаты {crawl_results[0].id}', 'crawl_results':crawl_results })

@login_required
def crawl3(request):
    crawl_scans = CrawlScan.objects.order_by('-id')
    print(len(crawl_scans))
    return render(request, 'main/crawl.html', {'title': 'Crawl Scans', 'crawl_scans': crawl_scans})





