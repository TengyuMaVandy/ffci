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
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

# REPOS_JSON_PATH = os.environ['FLASK_GITHUB_WEBHOOK_REPOS_JSON']
from django.views.generic import View
from git import Repo

from account.models import ReposStatus, GithubRepos, Account

failing_svg = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FFCI</title>
</head>
<body>
    <svg xmlns="http://www.w3.org/2000/svg" width="81" height="20">
        <linearGradient id="a" x2="0" y2="100%">
            <stop offset="0" stop-color="#bbb" stop-opacity=".1"></stop>
            <stop offset="1" stop-opacity=".1"></stop>
        </linearGradient>
        <rect rx="3" width="81" height="20" fill="#555"></rect>
        <rect rx="3" x="37" width="44" height="20" fill="#e05d44"></rect>
        <path fill="#e05d44" d="M37 0h4v20h-4z"></path>
        <rect rx="3" width="81" height="20" fill="url(#a)"></rect>
        <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
            <text x="19.5" y="15" fill="#010101" fill-opacity=".3">build</text>
            <text x="19.5" y="14">opls</text>
            <text x="58" y="15" fill="#010101" fill-opacity=".3">build</text>
            <text x="58" y="14">failing</text>
        </g>
    </svg>
</body>
</html>
'''

passing_svg = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FFCI</title>
</head>
<body>
    <svg xmlns="http://www.w3.org/2000/svg" width="90" height="20">
        <linearGradient id="a" x2="0" y2="100%">
            <stop offset="0" stop-color="#bbb" stop-opacity=".1"></stop>
            <stop offset="1" stop-opacity=".1"></stop>
        </linearGradient>
        <rect rx="3" width="90" height="20" fill="#555"></rect>
        <rect rx="3" x="37" width="53" height="20" fill="#4c1"></rect>
        <path fill="#4c1" d="M37 0h4v20h-4z"></path>
        <rect rx="3" width="90" height="20" fill="url(#a)"></rect>
        <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
            <text x="19.5" y="15" fill="#010101" fill-opacity=".3">build</text>
            <text x="19.5" y="14">opls</text>
            <text x="62.5" y="15" fill="#010101" fill-opacity=".3">build</text>
            <text x="62.5" y="14">passing</text>
        </g>
    </svg>
</body>
</html>
'''


def str_to_file(text, filename):
    """Write a file with the given name and the given text."""
    app_path = os.path.dirname(os.path.realpath(__file__))
    temp_path = os.path.join(app_path, "templates/hooks")
    file_path = os.path.join(temp_path, filename)
    output = open(file_path, "w")
    output.write(text)
    output.close()


class IndexView(View):
    template_name = 'hooks/index.html'

    @method_decorator(csrf_exempt)  # exempt csrf protect
    def dispatch(self, request, *args, **kwargs):
        return super(IndexView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)

    def post(self, request, *args, **kwargs):
        payload = json.loads(request.body.decode())
        # parse json to get info of repos & commit
        repo_meta = {
            'repo_author': payload['commits'][0]['author']['name'],
            'repo_name': payload['repository']['name'],
            'html_url': payload['repository']['html_url'],
            'repos_commit_sha': payload['commits'][0]['id'],
            'repos_commit_time': payload['commits'][0]['timestamp'],
            'repos_commit_message': payload['commits'][0]['message'],
        }
        author_name = repo_meta['repo_author']
        author_account_set = Account.objects.filter(github_name=author_name)
        author_token = author_account_set[0].github_token
        repo_name = repo_meta['repo_name']
        print("*** Trigger by git webhook ***")
        print("author: ", repo_meta['repo_author'])
        print("repo name: ", repo_meta['repo_name'])
        print("html url: ", repo_meta['html_url'])
        print("commit sha: ", repo_meta['repos_commit_sha'])
        print("commit time: ", repo_meta['repos_commit_time'])
        print("commit message: ", repo_meta['repos_commit_message'])
        print("*** Update repos ***")
        if request.META.get('HTTP_X_GITHUB_EVENT') == "ping":  # handle ping test
            return JsonResponse({'msg': 'Hi!'})
        if request.META.get('HTTP_X_GITHUB_EVENT') == "push":  # handle push
            # look for opls_test path
            path = os.path.split(foyer.__file__)[0]
            test_path = os.path.join(path, "tests/test_opls.py")
            print(test_path)

            # look for test repo
            hooked_repo_name = repo_name
            rw_dir = "default/home/path/ffci_repos"
            if sys.platform == "linux":
                rw_dir = "/home/tengyuma/ffci_repos"
            elif sys.platform == "win32":
                rw_dir = "E:/Users/TengyuMa/iModels/ffci_repos"
            repo_path = os.path.join(rw_dir, hooked_repo_name)
            hooked_repo = Repo(repo_path)
            hooked_repo.remote().pull()  # update test repo

            # run opls test
            print("*** Run opls test ***")
            cmd = "python -m pytest %s" % test_path  # use command line to run test
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, )  # run test
            repos_status_text = proc.communicate()[0].decode()  # get result .decode change byte to str
            hooked_repo_name = "opls_test"
            # get repos_status which is related to the hooked_repo
            if ReposStatus.objects.filter(github_repos__repos_name=hooked_repo_name).exists():
                repos_status = ReposStatus.objects.get(github_repos__repos_name=hooked_repo_name)
            else:
                hooked_repo_object = GithubRepos.objects.get(repos_name=hooked_repo_name)
                repos_status = ReposStatus.create(github_repos=hooked_repo_object, repos_status=repos_status_text)

            # save repos status
            repos_status.repos_commit_sha = repo_meta['repos_commit_sha']
            repos_status.repos_commit_time = repo_meta['repos_commit_time']
            repos_status.repos_commit_message = repo_meta['repos_commit_message']
            repos_status.repos_status = repos_status_text
            repos_status.save()

            # update svg tag of repos status
            server_url = "http://student20.metamds.org/"
            rw_dir = "default/home/path/ffci_repos"
            if sys.platform == "linux":
                server_url = "http://student20.metamds.org/"
                rw_dir = "/home/tengyuma/ffci_repos"
            elif sys.platform == "win32":
                server_url = "http://f7b5d17c.ngrok.io/"
                rw_dir = "E:/Users/TengyuMa/iModels/ffci_repos"
            repo_path = hooked_repo.working_tree_dir
            readme_path = os.path.join(repo_path, "README.md")
            last_status = "[![Build Status](%shooks/)](%saccount/github/hooks/)" % (server_url, server_url)
            if os.path.exists(readme_path):
                readme = open(readme_path, "r")
                old_readme_content = readme.read()
                readme_content = old_readme_content
                readme_content_line = readme_content.splitlines()
                line = [line for line in readme_content_line]
                if last_status not in readme_content:
                    if line:
                        line[0] = line[0] + "\n\n" + last_status
                    readme_content = "\n".join(line)
                else:
                    if line:
                        line[2] = last_status
                    readme_content = "\n".join(line)
                readme.close()
            else:
                old_readme_content = ""
                readme = open(readme_path, "w")
                readme_content = last_status + "\n\n"
                readme.close()

            readme = open(readme_path, "r+")
            if readme_content == old_readme_content:
                print("already had status tag")
                readme.close()
            else:
                print("add status tag")
                readme.write(readme_content)
                readme.close()
                hooked_repo.index.add([readme_path])
                hooked_repo.index.commit("add tag to readme")
                origin = hooked_repo.remotes['origin']
                # config remote origin, modify https auth url to give authorizations to push
                auth_https_url = "https://%s:%s@github.com/%s/%s.git" % (author_name, author_token, author_name, repo_name)
                cw = origin.config_writer
                cw.set("url", auth_https_url)
                cw.set("pushurl", auth_https_url)
                hooked_repo.remote().push()

            # readme_content.write(text)
            # readme_content.close()
            # split to get concise result to return
            failed_times = "0"
            passed_times = "0"
            # print("".join(repos_status_text))
            for repos_status_text_concise in re.split("==========================|=====================",
                                                      repos_status_text):
                if "failed" in repos_status_text_concise or "passed" in repos_status_text_concise:
                    if "failed" not in repos_status_text_concise:
                        str_to_file(text=passing_svg, filename='index.html')
                        passed_times = repos_status_text_concise.split("passed", 1)[0].replace(" ", "")
                    elif "passed" not in repos_status_text_concise:
                        str_to_file(text=failing_svg, filename='index.html')
                        failed_times = repos_status_text_concise.split("failed", 1)[0].replace(" ", "")
                    else:
                        str_to_file(text=failing_svg, filename='index.html')
                        failed_times = repos_status_text_concise.split("failed", 1)[0].replace(" ", "")
                        passed_times = repos_status_text_concise.split("passed", 1)[0].split(",")[1].replace(" ", "")
            test_result = failed_times + " failed, " + passed_times + " passed"
            print("*** Result of opls test ***")
            print(test_result)
            return JsonResponse({'msg': test_result})  # need escape \n in Json
        if request.META.get('HTTP_X_GITHUB_EVENT') == "pull_request":  # handle pull request
            return JsonResponse({'msg': "Do some algorithms for pull"})
        return HttpResponse('OK')


class StatusTagView(View):
    template_name = 'hooks/index.html'

    @method_decorator(csrf_exempt)  # exempt csrf protect
    def dispatch(self, request, *args, **kwargs):
        return super(StatusTagView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name)
