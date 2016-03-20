import io
import os
import re
import sys
import json
import subprocess
import ipaddress
import hmac
import hashlib
from hashlib import sha1
from django.http import HttpResponseForbidden
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

# REPOS_JSON_PATH = os.environ['FLASK_GITHUB_WEBHOOK_REPOS_JSON']


@csrf_exempt  # what's the meaning of this one
def index(request):
    if request.method == 'GET':
        return HttpResponse('OK')
    elif request.method == 'POST':
        payload = json.loads(request.body.decode())
        repo_meta = {
            'full_name': payload['repository']['full_name'],
            'html_url': payload['repository']['html_url'],
        }
        print(repo_meta)
        if request.META.get('HTTP_X_GITHUB_EVENT') == "ping":  # handle ping test
            return JsonResponse({'msg': 'Hi!'})
        if request.META.get('HTTP_X_GITHUB_EVENT') == "push":  # handle push
            return JsonResponse({'msg': "Do some algorithms for push"})
        if request.META.get('HTTP_X_GITHUB_EVENT') == "pull_request":  # handle pull request
            return JsonResponse({'msg': "Do some algorithms for pull"})
        return HttpResponse('OK')

