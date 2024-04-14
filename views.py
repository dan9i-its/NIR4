from django.shortcuts import render, redirect
from .models import FullScan, NucleiScan, NucleiTrigger, CrawlScan, Har, ZapScan, ZapTrigger, User, Comment, ProxyConfig
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

from django_ratelimit.decorators import ratelimit

import requests
from django.http import HttpResponseBadRequest

from rest_framework.views import APIView
from rest_framework.exceptions import PermissionDenied
from .middleware import create_access_token, check_refresh
SECRET_KEY = 'my_secret_key_123131231312313123123'
from oauth2_provider.views.generic import ProtectedResourceView

class ApiEndpoint(ProtectedResourceView):
    def get(self, request, *args, **kwargs):
        return HttpResponse('Hello, OAuth2!')


def oauth_sessions_generate_config(request):
    return render(request, 'main/oauth_config.html')



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



