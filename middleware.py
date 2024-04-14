from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponse, HttpRequest
import jwt
from datetime import datetime, timedelta
from django.shortcuts import render
import time 
from django.http import  HttpResponseForbidden



SECRET_KEY = 'my_secret_key_123131231312313123123'
def create_access_token(request):
    time_delta = timedelta(minutes=59)
    expiration_time = datetime.utcnow() + time_delta
    payload = {
        'role': 'admin',
        'exp': expiration_time,
        'type': 'access'
    }
    access_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return access_token


def get_token(request):
    time_delta = timedelta(days=50)
    expiration_time = datetime.utcnow() + time_delta
    payload = {
        'role': 'admin',
        'exp': expiration_time
    }
    
    refresh_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    access_token = create_access_token(request=request, refresh_token=refresh_token)
    return render(request, 'main/token.html', {'refresh_token': refresh_token, 'access_token': access_token})


def update_access(request):
    access_token = create_access_token(request)
    if check_refresh(request=request):
        return create_access_token(request=request)

def check_refresh(request):
    print("check_refresh")
    refresh = request.COOKIES.get('refresh')
    print(refresh)
    if refresh:
        payload = jwt.decode(refresh, SECRET_KEY, algorithms=['HS256'])
        expire = payload.get('exp')
        print(expire)
       
        if int(time.time())  <= int(expire) :
            return True
        else:
            return False

def check_access(request):
    print("check_access")
    access = request.COOKIES.get('access')
    print(access)
    if access:
        try:
            payload = jwt.decode(access, SECRET_KEY, algorithms=['HS256'])
            expire = payload.get('exp')
            print(expire)
            if int(time.time())  <= int(expire) :
                return True
            else:
                return False
        except Exception as err:
            return False


class AddAccessTokenMiddleware(MiddlewareMixin):
    def process_request(self, request):
        response = None
        # if check_access(request=request) or '/accounts/login' in request.path or '/get_token' in request.path:
        #     return response
        # else:
        #     return HttpResponseForbidden("Forbidden")
        pass
    def process_response(self, request, response):
        if check_refresh(request=request):
            print("updated_access")
            response.set_cookie('access', create_access_token(request), max_age=3600)
        return response

