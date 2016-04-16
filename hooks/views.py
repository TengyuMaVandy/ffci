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

import foyer
from django.http import HttpResponseForbidden
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


# REPOS_JSON_PATH = os.environ['FLASK_GITHUB_WEBHOOK_REPOS_JSON']
from account.models import ReposStatus, GithubRepos


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
        print("*** Trigger by git webhook ***\n", repo_meta)
        if request.META.get('HTTP_X_GITHUB_EVENT') == "ping":  # handle ping test
            return JsonResponse({'msg': 'Hi!'})
        if request.META.get('HTTP_X_GITHUB_EVENT') == "push":  # handle push
            path = os.path.split(foyer.__file__)[0]
            test_path = os.path.join(path, "tests/test_opls.py")
            print(test_path)
            cmd = "python -m pytest %s" % test_path  # use command line to run test
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,)  # run test
            repos_status_text = proc.communicate()[0].decode()  # get result .decode change byte to str
            hooked_repo_name = "opls_test"
            if ReposStatus.objects.filter(github_repos__repos_name=hooked_repo_name).exists():
                repos_status = ReposStatus.objects.get(github_repos__repos_name=hooked_repo_name)
            else:
                hooked_repo_object = GithubRepos.objects.get(repos_name=hooked_repo_name)
                repos_status = ReposStatus.create(github_repos=hooked_repo_object, repos_status=repos_status_text)
            repos_status.repos_status = repos_status_text
            repos_status.save()
            print("".join(repos_status_text))
            return JsonResponse({'msg': repos_status_text})  # need escape \n in Json
        if request.META.get('HTTP_X_GITHUB_EVENT') == "pull_request":  # handle pull request
            return JsonResponse({'msg': "Do some algorithms for pull"})
        return HttpResponse('OK')

