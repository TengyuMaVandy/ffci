from __future__ import unicode_literals

import hmac
import io
import json
import os
import os.path
import subprocess

import git
import re

from git import remote
from git import Repo
from hashlib import sha1

from django.http import Http404, HttpResponseForbidden, HttpResponse, JsonResponse
from django.shortcuts import redirect, get_object_or_404, render
from django.utils.http import base36_to_int, int_to_base36
from django.core.urlresolvers import reverse
from django.utils.translation import ugettext_lazy as _
from django.views.generic.base import TemplateResponseMixin, View
from django.views.generic.edit import FormView

from django.contrib import auth, messages
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth.tokens import default_token_generator

from account import signals
from account.conf import settings
from account.forms import SignupForm, LoginUsernameForm, GithubAuthForm, GithubReposForm, GithubHooksForm, \
    GithubHooksBackendForm
from account.forms import ChangePasswordForm, PasswordResetForm, PasswordResetTokenForm
from account.forms import SettingsForm
from account.hooks import hookset
from account.mixins import LoginRequiredMixin
from account.models import SignupCode, EmailAddress, EmailConfirmation, Account, AccountDeletion, GithubRepos, \
    GithubHooks
from account.utils import default_redirect, get_form_data

from github import Github


class SignupView(FormView):
    template_name = "account/signup.html"
    template_name_ajax = "account/ajax/signup.html"
    template_name_email_confirmation_sent = "account/email_confirmation_sent.html"
    template_name_email_confirmation_sent_ajax = "account/ajax/email_confirmation_sent.html"
    template_name_signup_closed = "account/signup_closed.html"
    template_name_signup_closed_ajax = "account/ajax/signup_closed.html"
    form_class = SignupForm
    form_kwargs = {}
    redirect_field_name = "next"
    identifier_field = "username"
    messages = {
        "email_confirmation_sent": {
            "level": messages.INFO,
            "text": _("Confirmation email sent to {email}.")
        },
        "invalid_signup_code": {
            "level": messages.WARNING,
            "text": _("The code {code} is invalid.")
        }
    }

    def __init__(self, *args, **kwargs):
        self.created_user = None
        self.created_account = None
        kwargs["signup_code"] = None
        super(SignupView, self).__init__(*args, **kwargs)

    def dispatch(self, request, *args, **kwargs):
        self.request = request
        self.args = args
        self.kwargs = kwargs
        self.setup_signup_code()
        return super(SignupView, self).dispatch(request, *args, **kwargs)

    def setup_signup_code(self):
        code = self.get_code()
        if code:
            try:
                self.signup_code = SignupCode.check_code(code)
            except SignupCode.InvalidCode:
                self.signup_code = None
            self.signup_code_present = True
        else:
            self.signup_code = None
            self.signup_code_present = False

    def get(self, *args, **kwargs):
        if self.request.user.is_authenticated():
            return redirect(default_redirect(self.request, settings.ACCOUNT_LOGIN_REDIRECT_URL))
        if not self.is_open():
            return self.closed()
        return super(SignupView, self).get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if self.request.user.is_authenticated():
            raise Http404()
        if not self.is_open():
            return self.closed()
        return super(SignupView, self).post(*args, **kwargs)

    def get_initial(self):
        initial = super(SignupView, self).get_initial()
        if self.signup_code:
            initial["code"] = self.signup_code.code
            if self.signup_code.email:
                initial["email"] = self.signup_code.email
        return initial

    def get_template_names(self):
        if self.request.is_ajax():
            return [self.template_name_ajax]
        else:
            return [self.template_name]

    def get_context_data(self, **kwargs):
        ctx = super(SignupView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        return ctx

    def get_form_kwargs(self):
        kwargs = super(SignupView, self).get_form_kwargs()
        kwargs.update(self.form_kwargs)
        return kwargs

    def form_invalid(self, form):
        signals.user_sign_up_attempt.send(
            sender=SignupForm,
            username=get_form_data(form, self.identifier_field),
            email=get_form_data(form, "email"),
            result=form.is_valid()
        )
        return super(SignupView, self).form_invalid(form)

    def form_valid(self, form):
        self.created_user = self.create_user(form, commit=False)
        # prevent User post_save signal from creating an Account instance
        # we want to handle that ourselves.
        self.created_user._disable_account_creation = True
        self.created_user.save()
        self.use_signup_code(self.created_user)
        email_address = self.create_email_address(form)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_REQUIRED and not email_address.verified:
            self.created_user.is_active = False
            self.created_user.save()
        self.created_account = self.create_account(form)
        self.create_github_repos(form)
        self.create_github_hooks(form)
        self.after_signup(form)
        # print(self.created_user.birthday)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_EMAIL and not email_address.verified:
            self.send_email_confirmation(email_address)
        if settings.ACCOUNT_EMAIL_CONFIRMATION_REQUIRED and not email_address.verified:
            return self.email_confirmation_required_response()
        else:
            show_message = [
                settings.ACCOUNT_EMAIL_CONFIRMATION_EMAIL,
                self.messages.get("email_confirmation_sent"),
                not email_address.verified
            ]
            if all(show_message):
                messages.add_message(
                    self.request,
                    self.messages["email_confirmation_sent"]["level"],
                    self.messages["email_confirmation_sent"]["text"].format(**{
                        "email": form.cleaned_data["email"]
                    })
                )
            # attach form to self to maintain compatibility with login_user
            # API. this should only be relied on by d-u-a and it is not a stable
            # API for site developers.
            self.form = form
            self.login_user()
        return redirect(self.get_success_url())

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_SIGNUP_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def create_user(self, form, commit=True, model=None, **kwargs):
        User = model
        if User is None:
            User = get_user_model()
        user = User(**kwargs)
        username = form.cleaned_data.get("username")
        if username is None:
            username = self.generate_username(form)
        user.username = username
        user.email = form.cleaned_data["email"].strip()
        # user.birthday = form.cleaned_data["birthday"]  # add birthday attribute here
        password = form.cleaned_data.get("password")
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        if commit:
            user.save()
        return user

    def create_account(self, form):
        github_token = form.cleaned_data.get("github_token")
        return Account.create(request=self.request, user=self.created_user, github_token=github_token,
                              create_email=False)

    def create_github_repos(self, form):
        account = self.created_account
        github_token = account.github_token
        g = Github(login_or_token=github_token)
        # create all of the user's github repositories into database
        for repo in g.get_user().get_repos(type="owner"):
            print(repo.name)
            GithubRepos.create(user=self.created_user, repos_name=repo.name)

    def create_github_hooks(self, form):
        # create hooks info for each repos related to the user
        for github_repos in GithubRepos.objects.filter(user=self.created_user):
            print(github_repos)
            GithubHooks.create(github_repos=github_repos, repos_hook=False)

    def generate_username(self, form):
        raise NotImplementedError(
            "Unable to generate username by default. "
            "Override SignupView.generate_username in a subclass."
        )

    def create_email_address(self, form, **kwargs):
        kwargs.setdefault("primary", True)
        kwargs.setdefault("verified", False)
        if self.signup_code:
            kwargs["verified"] = self.signup_code.email and self.created_user.email == self.signup_code.email
        return EmailAddress.objects.add_email(self.created_user, self.created_user.email, **kwargs)

    def use_signup_code(self, user):
        if self.signup_code:
            self.signup_code.use(user)

    def send_email_confirmation(self, email_address):
        email_address.send_confirmation(site=get_current_site(self.request))

    def after_signup(self, form):
        signals.user_signed_up.send(sender=SignupForm, user=self.created_user, form=form)

    def login_user(self):
        user = self.created_user
        if settings.ACCOUNT_USE_AUTH_AUTHENTICATE:
            # call auth.authenticate to ensure we set the correct backend for
            # future look ups using auth.get_user().
            user = auth.authenticate(**self.user_credentials())
        else:
            # set auth backend to ModelBackend, but this may not be used by
            # everyone. this code path is deprecated and will be removed in
            # favor of using auth.authenticate above.
            user.backend = "django.contrib.auth.backends.ModelBackend"
        auth.login(self.request, user)
        self.request.session.set_expiry(0)

    def user_credentials(self):
        return hookset.get_user_credentials(self.form, self.identifier_field)

    def get_code(self):
        return self.request.POST.get("code", self.request.GET.get("code"))

    def is_open(self):
        if self.signup_code:
            return True
        else:
            if self.signup_code_present:
                if self.messages.get("invalid_signup_code"):
                    messages.add_message(
                        self.request,
                        self.messages["invalid_signup_code"]["level"],
                        self.messages["invalid_signup_code"]["text"].format(**{
                            "code": self.get_code(),
                        })
                    )
        return settings.ACCOUNT_OPEN_SIGNUP

    def email_confirmation_required_response(self):
        if self.request.is_ajax():
            template_name = self.template_name_email_confirmation_sent_ajax
        else:
            template_name = self.template_name_email_confirmation_sent
        response_kwargs = {
            "request": self.request,
            "template": template_name,
            "context": {
                "email": self.created_user.email,
                "success_url": self.get_success_url(),
            }
        }
        return self.response_class(**response_kwargs)

    def closed(self):
        if self.request.is_ajax():
            template_name = self.template_name_signup_closed_ajax
        else:
            template_name = self.template_name_signup_closed
        response_kwargs = {
            "request": self.request,
            "template": template_name,
        }
        return self.response_class(**response_kwargs)


class LoginView(FormView):
    template_name = "account/login.html"
    template_name_ajax = "account/ajax/login.html"
    form_class = LoginUsernameForm
    form_kwargs = {}
    redirect_field_name = "next"

    def get(self, *args, **kwargs):
        if self.request.user.is_authenticated():
            return redirect(self.get_success_url())
        return super(LoginView, self).get(*args, **kwargs)

    def get_template_names(self):
        if self.request.is_ajax():
            return [self.template_name_ajax]
        else:
            return [self.template_name]

    def get_context_data(self, **kwargs):
        ctx = super(LoginView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        return ctx

    def get_form_kwargs(self):
        kwargs = super(LoginView, self).get_form_kwargs()
        kwargs.update(self.form_kwargs)
        return kwargs

    def form_invalid(self, form):
        signals.user_login_attempt.send(
            sender=LoginView,
            username=get_form_data(form, form.identifier_field),
            result=form.is_valid()
        )
        return super(LoginView, self).form_invalid(form)

    def form_valid(self, form):
        self.login_user(form)
        self.after_login(form)
        return redirect(self.get_success_url())

    def after_login(self, form):
        signals.user_logged_in.send(sender=LoginView, user=form.user, form=form)

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_LOGIN_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def login_user(self, form):
        auth.login(self.request, form.user)
        expiry = settings.ACCOUNT_REMEMBER_ME_EXPIRY if form.cleaned_data.get("remember") else 0
        self.request.session.set_expiry(expiry)


class LogoutView(TemplateResponseMixin, View):
    template_name = "account/logout.html"
    redirect_field_name = "next"

    def get(self, *args, **kwargs):
        if not self.request.user.is_authenticated():
            return redirect(self.get_redirect_url())
        ctx = self.get_context_data()
        return self.render_to_response(ctx)

    def post(self, *args, **kwargs):
        if self.request.user.is_authenticated():
            auth.logout(self.request)
        return redirect(self.get_redirect_url())

    def get_context_data(self, **kwargs):
        ctx = kwargs
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        return ctx

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_redirect_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_LOGOUT_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)


class ConfirmEmailView(TemplateResponseMixin, View):
    http_method_names = ["get", "post"]
    messages = {
        "email_confirmed": {
            "level": messages.SUCCESS,
            "text": _("You have confirmed {email}.")
        }
    }

    def get_template_names(self):
        return {
            "GET": ["account/email_confirm.html"],
            "POST": ["account/email_confirmed.html"],
        }[self.request.method]

    def get(self, *args, **kwargs):
        self.object = self.get_object()
        ctx = self.get_context_data()
        return self.render_to_response(ctx)

    def post(self, *args, **kwargs):
        self.object = confirmation = self.get_object()
        confirmation.confirm()
        self.after_confirmation(confirmation)
        redirect_url = self.get_redirect_url()
        if not redirect_url:
            ctx = self.get_context_data()
            return self.render_to_response(ctx)
        if self.messages.get("email_confirmed"):
            messages.add_message(
                self.request,
                self.messages["email_confirmed"]["level"],
                self.messages["email_confirmed"]["text"].format(**{
                    "email": confirmation.email_address.email
                })
            )
        return redirect(redirect_url)

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        try:
            return queryset.get(key=self.kwargs["key"].lower())
        except EmailConfirmation.DoesNotExist:
            raise Http404()

    def get_queryset(self):
        qs = EmailConfirmation.objects.all()
        qs = qs.select_related("email_address__user")
        return qs

    def get_context_data(self, **kwargs):
        ctx = kwargs
        ctx["confirmation"] = self.object
        return ctx

    def get_redirect_url(self):
        if self.request.user.is_authenticated():
            if not settings.ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL:
                return settings.ACCOUNT_LOGIN_REDIRECT_URL
            return settings.ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL
        else:
            return settings.ACCOUNT_EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL

    def after_confirmation(self, confirmation):
        user = confirmation.email_address.user
        user.is_active = True
        user.save()


class ChangePasswordView(FormView):
    template_name = "ci_account/password_change.html"
    form_class = ChangePasswordForm
    redirect_field_name = "next"
    messages = {
        "password_changed": {
            "level": messages.SUCCESS,
            "text": _("Password successfully changed.")
        }
    }

    def get(self, *args, **kwargs):
        if not self.request.user.is_authenticated():
            return redirect("account_password_reset")
        return super(ChangePasswordView, self).get(*args, **kwargs)

    def post(self, *args, **kwargs):
        if not self.request.user.is_authenticated():
            return HttpResponseForbidden()
        return super(ChangePasswordView, self).post(*args, **kwargs)

    def change_password(self, form):
        user = self.request.user
        user.set_password(form.cleaned_data["password_new"])
        user.save()
        # required on Django >= 1.7 to keep the user authenticated
        if hasattr(auth, "update_session_auth_hash"):
            auth.update_session_auth_hash(self.request, user)

    def after_change_password(self):
        user = self.request.user
        signals.password_changed.send(sender=ChangePasswordView, user=user)
        if settings.ACCOUNT_NOTIFY_ON_PASSWORD_CHANGE:
            self.send_email(user)
        if self.messages.get("password_changed"):
            messages.add_message(
                self.request,
                self.messages["password_changed"]["level"],
                self.messages["password_changed"]["text"]
            )

    def get_form_kwargs(self):
        """
        Returns the keyword arguments for instantiating the form.
        """
        kwargs = {"user": self.request.user, "initial": self.get_initial()}
        if self.request.method in ["POST", "PUT"]:
            kwargs.update({
                "data": self.request.POST,
                "files": self.request.FILES,
            })
        return kwargs

    def form_valid(self, form):
        self.change_password(form)
        self.after_change_password()
        return redirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        ctx = super(ChangePasswordView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        return ctx

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_PASSWORD_CHANGE_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def send_email(self, user):
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        current_site = get_current_site(self.request)
        ctx = {
            "user": user,
            "protocol": protocol,
            "current_site": current_site,
        }
        hookset.send_password_change_email([user.email], ctx)


class PasswordResetView(FormView):
    template_name = "account/password_reset.html"
    template_name_sent = "account/password_reset_sent.html"
    form_class = PasswordResetForm
    token_generator = default_token_generator

    def get_context_data(self, **kwargs):
        context = super(PasswordResetView, self).get_context_data(**kwargs)
        if self.request.method == "POST" and "resend" in self.request.POST:
            context["resend"] = True
        return context

    def form_valid(self, form):
        self.send_email(form.cleaned_data["email"])
        response_kwargs = {
            "request": self.request,
            "template": self.template_name_sent,
            "context": self.get_context_data(form=form)
        }
        return self.response_class(**response_kwargs)

    def send_email(self, email):
        User = get_user_model()
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        current_site = get_current_site(self.request)
        email_qs = EmailAddress.objects.filter(email__iexact=email)
        for user in User.objects.filter(pk__in=email_qs.values("user")):
            uid = int_to_base36(user.id)
            token = self.make_token(user)
            password_reset_url = "{0}://{1}{2}".format(
                protocol,
                current_site.domain,
                reverse("account_password_reset_token", kwargs=dict(uidb36=uid, token=token))
            )
            ctx = {
                "user": user,
                "current_site": current_site,
                "password_reset_url": password_reset_url,
            }
            hookset.send_password_reset_email([user.email], ctx)

    def make_token(self, user):
        return self.token_generator.make_token(user)


class PasswordResetTokenView(FormView):
    template_name = "account/password_reset_token.html"
    template_name_fail = "account/password_reset_token_fail.html"
    form_class = PasswordResetTokenForm
    token_generator = default_token_generator
    redirect_field_name = "next"
    messages = {
        "password_changed": {
            "level": messages.SUCCESS,
            "text": _("Password successfully changed.")
        },
    }

    def get(self, request, **kwargs):
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        ctx = self.get_context_data(form=form)
        if not self.check_token(self.get_user(), self.kwargs["token"]):
            return self.token_fail()
        return self.render_to_response(ctx)

    def get_context_data(self, **kwargs):
        ctx = super(PasswordResetTokenView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "uidb36": self.kwargs["uidb36"],
            "token": self.kwargs["token"],
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        return ctx

    def change_password(self, form):
        user = self.get_user()
        user.set_password(form.cleaned_data["password"])
        user.save()

    def after_change_password(self):
        user = self.get_user()
        signals.password_changed.send(sender=PasswordResetTokenView, user=user)
        if settings.ACCOUNT_NOTIFY_ON_PASSWORD_CHANGE:
            self.send_email(user)
        if self.messages.get("password_changed"):
            messages.add_message(
                self.request,
                self.messages["password_changed"]["level"],
                self.messages["password_changed"]["text"]
            )

    def form_valid(self, form):
        self.change_password(form)
        self.after_change_password()
        return redirect(self.get_success_url())

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_PASSWORD_RESET_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)

    def get_user(self):
        try:
            uid_int = base36_to_int(self.kwargs["uidb36"])
        except ValueError:
            raise Http404()
        return get_object_or_404(get_user_model(), id=uid_int)

    def check_token(self, user, token):
        return self.token_generator.check_token(user, token)

    def token_fail(self):
        response_kwargs = {
            "request": self.request,
            "template": self.template_name_fail,
            "context": self.get_context_data()
        }
        return self.response_class(**response_kwargs)

    def send_email(self, user):
        protocol = getattr(settings, "DEFAULT_HTTP_PROTOCOL", "http")
        current_site = get_current_site(self.request)
        ctx = {
            "user": user,
            "protocol": protocol,
            "current_site": current_site,
        }
        hookset.send_password_change_email([user.email], ctx)


class SettingsView(LoginRequiredMixin, FormView):
    template_name = "ci_account/settings.html"
    form_class = SettingsForm
    redirect_field_name = "next"
    messages = {
        "settings_updated": {
            "level": messages.SUCCESS,
            "text": _("Account settings updated.")
        },
    }

    def get_form_class(self):
        # @@@ django: this is a workaround to not having a dedicated method
        # to initialize self with a request in a known good state (of course
        # this only works with a FormView)
        self.primary_email_address = EmailAddress.objects.get_primary(self.request.user)
        return super(SettingsView, self).get_form_class()

    def get_initial(self):
        initial = super(SettingsView, self).get_initial()
        if self.primary_email_address:
            initial["email"] = self.primary_email_address.email
        initial["timezone"] = self.request.user.account.timezone
        initial["language"] = self.request.user.account.language
        initial["birthday"] = self.request.user.account.birthday
        return initial

    def form_valid(self, form):
        self.update_settings(form)
        if self.messages.get("settings_updated"):
            messages.add_message(
                self.request,
                self.messages["settings_updated"]["level"],
                self.messages["settings_updated"]["text"]
            )
        return redirect(self.get_success_url())

    def update_settings(self, form):
        self.update_email(form)
        self.update_account(form)

    def update_email(self, form, confirm=None):
        user = self.request.user
        if confirm is None:
            confirm = settings.ACCOUNT_EMAIL_CONFIRMATION_EMAIL
        # @@@ handle multiple emails per user
        email = form.cleaned_data["email"].strip()
        if not self.primary_email_address:
            user.email = email
            EmailAddress.objects.add_email(self.request.user, email, primary=True, confirm=confirm)
            user.save()
        else:
            if email != self.primary_email_address.email:
                self.primary_email_address.change(email, confirm=confirm)

    def get_context_data(self, **kwargs):
        ctx = super(SettingsView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        return ctx

    def update_account(self, form):
        fields = {}
        if "timezone" in form.cleaned_data:
            fields["timezone"] = form.cleaned_data["timezone"]
        if "language" in form.cleaned_data:
            fields["language"] = form.cleaned_data["language"]
        if "birthday" in form.cleaned_data:  # add birthday field here
            fields["birthday"] = form.cleaned_data["birthday"]
        if fields:
            account = self.request.user.account
            for k, v in fields.items():
                setattr(account, k, v)
            account.save()

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_SETTINGS_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)


class DeleteView(LogoutView):
    template_name = "ci_account/delete.html"
    messages = {
        "account_deleted": {
            "level": messages.WARNING,
            "text": _("Your account is now inactive and your data will be expunged in the next {expunge_hours} hours.")
        },
    }

    def post(self, *args, **kwargs):
        AccountDeletion.mark(self.request.user)
        auth.logout(self.request)
        messages.add_message(
            self.request,
            self.messages["account_deleted"]["level"],
            self.messages["account_deleted"]["text"].format(**{
                "expunge_hours": settings.ACCOUNT_DELETION_EXPUNGE_HOURS,
            })
        )
        return redirect(self.get_redirect_url())

    def get_context_data(self, **kwargs):
        ctx = super(DeleteView, self).get_context_data(**kwargs)
        ctx.update(kwargs)
        ctx["ACCOUNT_DELETION_EXPUNGE_HOURS"] = settings.ACCOUNT_DELETION_EXPUNGE_HOURS
        return ctx


class GithubAuthView(FormView):  # need modify GithubAuthView in the future
    template_name = "ci_account/github_auth.html"
    form_class = GithubAuthForm
    redirect_field_name = "next"
    messages = {
        "Github_Auth_updated": {
            "level": messages.SUCCESS,
            "text": _("Account github auth updated.")
        },
    }

    def get_initial(self):
        initial = super(GithubAuthView, self).get_initial()
        initial["github_token"] = self.request.user.account.github_token
        return initial

    def form_valid(self, form):
        self.update_github_auth(form)
        if self.messages.get("Github_Auth_updated"):
            messages.add_message(
                self.request,
                self.messages["Github_Auth_updated"]["level"],
                self.messages["Github_Auth_updated"]["text"]
            )
        return redirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        ctx = super(GithubAuthView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        return ctx

    def update_github_auth(self, form):
        fields = {}
        if "github_token" in form.cleaned_data:
            fields["github_token"] = form.cleaned_data["github_token"]
        if fields:
            account = self.request.user.account
            for k, v in fields.items():
                setattr(account, k, v)
            account.save()

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_GITHUB_AUTH_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)


class GithubReposView(FormView):  # need modify GithubRepos in the future 3/13/16
    template_name = "ci_account/github_repos.html"
    form_class = GithubReposForm
    # second_form_class = GithubReposHooksForm  # try to modify the forms' layout
    redirect_field_name = "next"
    messages = {
        "Github_Repos_updated": {
            "level": messages.SUCCESS,
            "text": _("Account github repos updated.")
        },
    }

    def get(self, request, *args, **kwargs):
        form = self.form_class(user=self.request.user, initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(self.request.user, request.POST)
        if form.is_valid():
            self.form_valid(form)
        return render(request, self.template_name, {'form': form})

    def get_initial(self):  # need more efficient and dynamic way to do this!
        initial = super(GithubReposView, self).get_initial()
        # use original way
        # initial["github_repos"] = self.request.user.githubrepos.github_repos
        # initial["github_repos_hook"] = self.request.user.githubrepos.github_repos_hook
        # """ try new class GithubRepos
        # initial repos
        # initial["github_repos1"] = self.request.user.account.github_repos1
        # initial["github_repos2"] = self.request.user.account.github_repos2
        # initial["github_repos3"] = self.request.user.account.github_repos3
        # initial["github_repos4"] = self.request.user.account.github_repos4
        # initial["github_repos5"] = self.request.user.account.github_repos5
        # initial["github_repos6"] = self.request.user.account.github_repos6
        # initial["github_repos7"] = self.request.user.account.github_repos7
        # initial["github_repos8"] = self.request.user.account.github_repos8
        # initial["github_repos9"] = self.request.user.account.github_repos9
        # initial["github_repos10"] = self.request.user.account.github_repos10
        # initial["github_repos11"] = self.request.user.account.github_repos11
        # initial["github_repos12"] = self.request.user.account.github_repos12
        # initial["github_repos13"] = self.request.user.account.github_repos13
        # initial["github_repos14"] = self.request.user.account.github_repos14
        # initial["github_repos15"] = self.request.user.account.github_repos15
        # initial["github_repos16"] = self.request.user.account.github_repos16
        # initial["github_repos17"] = self.request.user.account.github_repos17
        # initial["github_repos18"] = self.request.user.account.github_repos18
        # initial["github_repos19"] = self.request.user.account.github_repos19
        # initial["github_repos20"] = self.request.user.account.github_repos20
        # # try ComboField Doesn't work
        # # initial repos _hookhook
        # initial["github_repos1_hook"] = self.request.user.account.github_repos1_hook
        # initial["github_repos2_hook"] = self.request.user.account.github_repos2_hook
        # initial["github_repos3_hook"] = self.request.user.account.github_repos3_hook
        # initial["github_repos4_hook"] = self.request.user.account.github_repos4_hook
        # initial["github_repos5_hook"] = self.request.user.account.github_repos5_hook
        # initial["github_repos6_hook"] = self.request.user.account.github_repos6_hook
        # initial["github_repos7_hook"] = self.request.user.account.github_repos7_hook
        # initial["github_repos8_hook"] = self.request.user.account.github_repos8_hook
        # initial["github_repos9_hook"] = self.request.user.account.github_repos9_hook
        # initial["github_repos10_hook"] = self.request.user.account.github_repos10_hook
        # initial["github_repos11_hook"] = self.request.user.account.github_repos11_hook
        # initial["github_repos12_hook"] = self.request.user.account.github_repos12_hook
        # initial["github_repos13_hook"] = self.request.user.account.github_repos13_hook
        # initial["github_repos14_hook"] = self.request.user.account.github_repos14_hook
        # initial["github_repos15_hook"] = self.request.user.account.github_repos15_hook
        # initial["github_repos16_hook"] = self.request.user.account.github_repos16_hook
        # initial["github_repos17_hook"] = self.request.user.account.github_repos17_hook
        # initial["github_repos18_hook"] = self.request.user.account.github_repos18_hook
        # initial["github_repos19_hook"] = self.request.user.account.github_repos19_hook
        # initial["github_repos20_hook"] = self.request.user.account.github_repos20_hook
        # """
        return initial

    def form_valid(self, form):
        self.update_github_repos(form)
        print("repo valid here")
        if self.messages.get("Github_Repos_updated"):
            messages.add_message(
                self.request,
                self.messages["Github_Repos_updated"]["level"],
                self.messages["Github_Repos_updated"]["text"]
            )
        return redirect(self.get_success_url())

    # def get_object(self):  # change method to modify forms' layout
    #     return get_object_or_404(Model, pk=self.request.session['someval'])
    #
    # def form_invalid(self, **kwargs):
    #     return self.render_to_response(self.get_context_data(**kwargs))

    def get_context_data(self, **kwargs):
        ctx = super(GithubReposView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        # if 'form' not in ctx:  # change method to modify the forms' layout
        #     ctx['form'] = self.form_class(initial={'some_field': ctx['model'].some_field})
        # if 'form2' not in ctx:
        #     ctx['form2'] = self.second_form_class(initial={'another_field': ctx['model'].another_field})
        return ctx

    def update_github_repos(self, form):  # user github library here, collect all repos from github
        account = self.request.user.account
        github_token = account.github_token
        g = Github(login_or_token=github_token)
        # create hook parameter
        server_url = "http://8f2e6dbe.ngrok.io/hooks/"  # we need change server_url when our server's url changed
        hook_config_url_list = []  # initial hook config url list in order to check already existed hooks
        hook_name = "web"
        hook_config = {"url": server_url, "content_type": "json"}
        hook_active = True
        hook_events = ["push", "pull_request"]
        repos_field = {}
        i = 0
        for repo in g.get_user().get_repos(type="owner"):
            # print(g.get_user().get_repo(repo.name).get_hooks())
            repos_field["github_repos%d" % i] = repo.name
            hooks_list = [hooks_list for hooks_list in g.get_user().get_repo(repo.name).get_hooks()]
            if "repos%d_hook" % i in form.cleaned_data:
                # fields["github_repos%d_hook" % i] = form.cleaned_data["repos%d_hook" % i]  test new model
                if form.cleaned_data["repos%d_hook" % i]:
                    print("create hook")
                    print("check existed hooks")
                    """ handle hook automatically with github """
                    if [hook for hook in hooks_list]:  # check existed hooks
                        for hook in hooks_list:  # check existed hooks with our server
                            hook_config_url_list = hook_config_url_list + [hook.config["url"], ]
                        print(hook_config_url_list)
                        if server_url in hook_config_url_list:
                            print("Hook already exists")
                        else:
                            g.get_user().get_repo(repo.name).create_hook(name=hook_name, config=hook_config,
                                                                         active=hook_active, events=hook_events)
                            print("create successfully")
                    else:
                        print("no existed hooks, create a new one")
                        g.get_user().get_repo(repo.name).create_hook(name=hook_name, config=hook_config,
                                                                     active=hook_active, events=hook_events)
                        print("no hooks before, create successfully")
                else:
                    print("delete hook")
                    for hook in hooks_list:  # handle delete hooks
                        # print(hook.config)
                        if "url" in hook.config:
                            if server_url == hook.config["url"]:
                                g.get_user().get_repo(repo.name).get_hook(id=hook.id).delete()
                                print("delete successfully")
                            else:
                                print("no hook to delete")
                        else:
                            print("hook.config doesn't have url")
            i += 1
            # g.get_user().get_repo()
            # GithubReposForm.github_repos1_hook.label = repo.name
        repos_name = [repos.repos_name for repos in GithubRepos.objects.filter(user=self.request.user)]
        # repos = [repos for repos in GithubRepos.objects.filter(user=self.request.user)]
        if repos_field:
            for repos in GithubRepos.objects.filter(user=self.request.user):
                for k, v in repos_field.items():
                    print(k, v)
                    if v in repos_name:
                        if v == repos.repos_name:
                            setattr(repos, k, v)
                            repos_hook = GithubHooks.objects.get(github_repos=repos)
                            repos_hook.repos_hook = form.cleaned_data["%s_hook" % k]
                            repos_hook.save()
                    else:
                        github_repos = GithubRepos.create(user=self.request.user, repos_name=v)
                        repos_hook = form.cleaned_data["%s_hook" % k]
                        GithubHooks.create(github_repos=github_repos, repos_hook=repos_hook)
                repos.save()

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_GITHUB_REPOS_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)


class GithubHooksView(FormView):  # Add GithubHooksView to handle github webhook 3/14/16
    template_name = "ci_account/github_hooks.html"
    form_class = GithubHooksForm
    # second_form_class = GithubReposHooksForm  # try to modify the forms' layout
    redirect_field_name = "next"
    messages = {
        "Github_Hooks_updated": {
            "level": messages.SUCCESS,
            "text": _("Account github hooks updated.")
        },
    }

    def get(self, request, *args, **kwargs):
        form = self.form_class(user=self.request.user, initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(self.request.user, request.POST)
        if form.is_valid():
            self.form_valid(form)
        return render(request, self.template_name, {'form': form})

    def get_initial(self):  # need more efficient and dynamic way to do this!
        initial = super(GithubHooksView, self).get_initial()
        return initial

    def form_valid(self, form):
        self.update_github_hooks(form)
        # self.hooked_command(form)
        if self.messages.get("Github_Hooks_updated"):
            messages.add_message(
                self.request,
                self.messages["Github_Hooks_updated"]["level"],
                self.messages["Github_Hooks_updated"]["text"]
            )
        return redirect(self.get_success_url())

    # def get_object(self):  # change method to modify forms' layout
    #     return get_object_or_404(Model, pk=self.request.session['someval'])
    #
    # def form_invalid(self, **kwargs):
    #     return self.render_to_response(self.get_context_data(**kwargs))

    def get_context_data(self, **kwargs):
        ctx = super(GithubHooksView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        # if 'form' not in ctx:  # change method to modify the forms' layout
        #     ctx['form'] = self.form_class(initial={'some_field': ctx['model'].some_field})
        # if 'form2' not in ctx:
        #     ctx['form2'] = self.second_form_class(initial={'another_field': ctx['model'].another_field})
        return ctx

    # def hooked_command(self, form):  # git command for hooked repo

    def update_github_hooks(self, form):  # user github library here, collect all repos from github
        print(form.cleaned_data["github_hooked_repo"],
              form.cleaned_data["github_hooked_command"])  # show which repo and which command
        # hooked_repo_number = form.cleaned_data["github_hooked_repo"]
        hooked_repo_command = form.cleaned_data["github_hooked_command"]
        print(dict(form.fields["github_hooked_repo"].choices)[
                  form.cleaned_data["github_hooked_repo"]])  # show hooked_repo_name
        hooked_repo_name = dict(form.fields["github_hooked_repo"].choices)[form.cleaned_data["github_hooked_repo"]]
        rw_dir = "E:/Users/TengyuMa/MoleculeCI"
        repo_path = os.path.join(rw_dir, hooked_repo_name)
        print(repo_path)
        account = self.request.user.account
        github_token = account.github_token  # get github personal accessing token
        g = Github(login_or_token=github_token)  # github api based on personal token
        print(g.get_user().get_repo(hooked_repo_name).clone_url)
        # hooked_repo_url = g.get_user().get_repo(hooked_repo_name).url
        hooked_repo_clone_url = g.get_user().get_repo(hooked_repo_name).clone_url  # hooked_repo url
        if not os.path.exists(repo_path):  # check already existed or not
            hooked_repo = git.Repo.clone_from(url=hooked_repo_clone_url,
                                              to_path=repo_path)  # pull down hooked_repo to local
        else:
            hooked_repo = Repo(repo_path)
        if hooked_repo_command == "clone":
            print("clone automatically :P")
        if hooked_repo_command == "pull":
            hooked_repo.remote().pull()
        if hooked_repo_command == "push":
            # hooked_repo.remote().push()
            print("We need some algorithms to decide how to modify our local repo, then we can git push")
        if hooked_repo_command == "add":
            # hooked_repo.git.add()
            print("We need some algorithms to decide how to modify our local repo, then we can git add")
        if hooked_repo_command == "rm":
            print("We need some algorithms to decide how to modify our local repo, then we can git rm")
            # hooked_repo.git.rm()
        if hooked_repo_command == "commit":
            # hooked_repo.git.commit()
            print("We need some algorithms to decide how to modify our local repo, then we can git commit")


            # account = self.request.user.account
            # github_token = account.github_token
            # g = Github(login_or_token=github_token)
            # print("hello world")
            # fields = {}
            # i = 0
            # for repo in g.get_user().get_repos():
            #     i += 1
            #     fields["github_repos%d" % i] = repo.name
            #     if "github_repos%d_hook" % i in form.cleaned_data:
            #         fields["github_repos%d_hook" % i] = form.cleaned_data["github_repos%d_hook" % i]
            #         # GithubReposForm.github_repos1_hook.label = repo.name
            # if fields:
            #     for k, v in fields.items():
            #         setattr(account, k, v)
            #     account.save()

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_GITHUB_HOOKS_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)


class GithubHooksBackendView(FormView):  # Add GithubHooksView to handle github webhook 3/14/16
    template_name = "ci_account/github_hooks_backend.html"
    form_class = GithubHooksBackendForm
    # second_form_class = GithubReposHooksForm  # try to modify the forms' layout
    redirect_field_name = "next"
    messages = {
        "Github_Hooks_updated": {
            "level": messages.SUCCESS,
            "text": _("Account github hooks updated.")
        },
    }

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        if request.META.get('HTTP_X_GITHUB_EVENT') == "ping":
            return JsonResponse({'msg': 'Hi!'})
        if request.META.get('HTTP_X_GITHUB_EVENT') != "push":  # push to issues 2/24/16
            return JsonResponse({'msg': "wrong event type"})
        # repos = json.loads(io.open(REPOS_JSON_PATH, 'r').read())
        # print(request.body)
        payload = json.loads(request.body.decode())
        repo_meta = {
            'name': payload['repository']['name'],
            'owner': payload['repository']['owner']['name'],
        }

        # Try to match on branch as configured in repos.json
        match = re.match(r"refs/heads/(?P<branch>.*)", payload['ref'])
        if match:
            repo_meta['branch'] = match.groupdict()['branch']
            repo = repos.get(
                '{owner}/{name}/branch:{branch}'.format(**repo_meta), None)

            # Fallback to plain owner/name lookup
            if not repo:
                repo = repos.get('{owner}/{name}'.format(**repo_meta), None)

        if repo and repo.get('path', None):
            # Check if POST request signature is valid
            key = repo.get('key', None)
            if key:
                signature = request.META.get('HTTP_X_HUB_SIGNATURE').split(
                    '=')[1]
                key = key.encode()
                mac = hmac.new(key, request.body, digestmod=sha1)
                if not hmac.compare_digest(mac.hexdigest(), signature):
                    return HttpResponseForbidden()

        if repo.get('action', None):
            for action in repo['action']:
                subp = subprocess.Popen(action, cwd=repo.get('path', '.'), shell=True)
                subp.wait()
        return HttpResponse('OK')

    def get_initial(self):  # need more efficient and dynamic way to do this!
        initial = super(GithubHooksBackendView, self).get_initial()
        return initial

    def form_valid(self, form):
        self.update_github_hooks(form)
        # self.hooked_command(form)
        if self.messages.get("Github_Hooks_Backend_updated"):
            messages.add_message(
                self.request,
                self.messages["Github_Hooks_Backend_updated"]["level"],
                self.messages["Github_Hooks_Backend_updated"]["text"]
            )
        return redirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        ctx = super(GithubHooksBackendView, self).get_context_data(**kwargs)
        redirect_field_name = self.get_redirect_field_name()
        ctx.update({
            "redirect_field_name": redirect_field_name,
            "redirect_field_value": self.request.POST.get(redirect_field_name,
                                                          self.request.GET.get(redirect_field_name, "")),
        })
        # if 'form' not in ctx:  # change method to modify the forms' layout
        #     ctx['form'] = self.form_class(initial={'some_field': ctx['model'].some_field})
        # if 'form2' not in ctx:
        #     ctx['form2'] = self.second_form_class(initial={'another_field': ctx['model'].another_field})
        return ctx

    # def hooked_command(self, form):  # git command for hooked repo

    def update_github_hooks(self, form):  # user github library here, collect all repos from github
        print("update_github_hooks")

    def get_redirect_field_name(self):
        return self.redirect_field_name

    def get_success_url(self, fallback_url=None, **kwargs):
        if fallback_url is None:
            fallback_url = settings.ACCOUNT_GITHUB_HOOKS_REDIRECT_URL
        kwargs.setdefault("redirect_field_name", self.get_redirect_field_name())
        return default_redirect(self.request, fallback_url, **kwargs)
