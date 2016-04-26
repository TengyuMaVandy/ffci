from __future__ import unicode_literals

import re

from django.forms import SelectDateWidget, ComboField, CharField, BooleanField

try:
    from collections import OrderedDict
except ImportError:
    OrderedDict = None

from django import forms
from django.utils.translation import ugettext_lazy as _

from django.contrib import auth
from django.contrib.auth import get_user_model

from account.conf import settings
from account.hooks import hookset
from account.models import EmailAddress, Account, GithubRepos, GithubHooks, ReposStatus
from account.utils import get_user_lookup_kwargs

from crispy_forms.helper import FormHelper

alnum_re = re.compile(r"^\w+$")


class SignupForm(forms.Form):
    username = forms.CharField(
        label=_("Username"),
        max_length=30,
        widget=forms.TextInput(),
        required=True
    )
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(render_value=False)
    )
    password_confirm = forms.CharField(
        label=_("Password (again)"),
        widget=forms.PasswordInput(render_value=False)
    )
    email = forms.EmailField(
        label=_("Email"),
        widget=forms.TextInput(), required=True
    )
    github_token = forms.CharField(
        label=_("Github token"),
        max_length=255, required=True
    )
    # birthday = forms.DateField(widget=SelectDateWidget(years=range(1910, 1991)))

    code = forms.CharField(
        max_length=64,
        required=False,
        widget=forms.HiddenInput()
    )

    def clean_username(self):
        if not alnum_re.search(self.cleaned_data["username"]):
            raise forms.ValidationError(_("Usernames can only contain letters, numbers and underscores."))
        User = get_user_model()
        lookup_kwargs = get_user_lookup_kwargs({
            "{username}__iexact": self.cleaned_data["username"]
        })
        qs = User.objects.filter(**lookup_kwargs)
        if not qs.exists():
            return self.cleaned_data["username"]
        raise forms.ValidationError(_("This username is already taken. Please choose another."))

    def clean_email(self):
        value = self.cleaned_data["email"]
        qs = EmailAddress.objects.filter(email__iexact=value)
        if not qs.exists() or not settings.ACCOUNT_EMAIL_UNIQUE:
            return value
        raise forms.ValidationError(_("A user is registered with this email address."))

    def clean(self):
        if "password" in self.cleaned_data and "password_confirm" in self.cleaned_data:
            if self.cleaned_data["password"] != self.cleaned_data["password_confirm"]:
                raise forms.ValidationError(_("You must type the same password each time."))
        return self.cleaned_data


class LoginForm(forms.Form):
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(render_value=False)
    )
    remember = forms.BooleanField(
        label=_("Remember Me"),
        required=False
    )
    user = None

    def clean(self):
        if self._errors:
            return
        user = auth.authenticate(**self.user_credentials())
        if user:
            if user.is_active:
                self.user = user
            else:
                raise forms.ValidationError(_("This account is inactive."))
        else:
            raise forms.ValidationError(self.authentication_fail_message)
        return self.cleaned_data

    def user_credentials(self):
        return hookset.get_user_credentials(self, self.identifier_field)


class LoginUsernameForm(LoginForm):
    username = forms.CharField(label=_("Username"), max_length=30)
    authentication_fail_message = _("The username and/or password you specified are not correct.")
    identifier_field = "username"

    def __init__(self, *args, **kwargs):
        super(LoginUsernameForm, self).__init__(*args, **kwargs)
        field_order = ["username", "password", "remember"]
        if not OrderedDict or hasattr(self.fields, "keyOrder"):
            self.fields.keyOrder = field_order
        else:
            self.fields = OrderedDict((k, self.fields[k]) for k in field_order)


class LoginEmailForm(LoginForm):
    email = forms.EmailField(label=_("Email"))
    authentication_fail_message = _("The email address and/or password you specified are not correct.")
    identifier_field = "email"

    def __init__(self, *args, **kwargs):
        super(LoginEmailForm, self).__init__(*args, **kwargs)
        field_order = ["email", "password", "remember"]
        if not OrderedDict or hasattr(self.fields, "keyOrder"):
            self.fields.keyOrder = field_order
        else:
            self.fields = OrderedDict((k, self.fields[k]) for k in field_order)


class ChangePasswordForm(forms.Form):
    password_current = forms.CharField(
        label=_("Current Password"),
        widget=forms.PasswordInput(render_value=False)
    )
    password_new = forms.CharField(
        label=_("New Password"),
        widget=forms.PasswordInput(render_value=False)
    )
    password_new_confirm = forms.CharField(
        label=_("New Password (again)"),
        widget=forms.PasswordInput(render_value=False)
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop("user")
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def clean_password_current(self):
        if not self.user.check_password(self.cleaned_data.get("password_current")):
            raise forms.ValidationError(_("Please type your current password."))
        return self.cleaned_data["password_current"]

    def clean_password_new_confirm(self):
        if "password_new" in self.cleaned_data and "password_new_confirm" in self.cleaned_data:
            if self.cleaned_data["password_new"] != self.cleaned_data["password_new_confirm"]:
                raise forms.ValidationError(_("You must type the same password each time."))
        return self.cleaned_data["password_new_confirm"]


class PasswordResetForm(forms.Form):
    email = forms.EmailField(label=_("Email"), required=True)

    def clean_email(self):
        value = self.cleaned_data["email"]
        if not EmailAddress.objects.filter(email__iexact=value).exists():
            raise forms.ValidationError(_("Email address can not be found."))
        return value


class PasswordResetTokenForm(forms.Form):
    password = forms.CharField(
        label=_("New Password"),
        widget=forms.PasswordInput(render_value=False)
    )
    password_confirm = forms.CharField(
        label=_("New Password (again)"),
        widget=forms.PasswordInput(render_value=False)
    )

    def clean_password_confirm(self):
        if "password" in self.cleaned_data and "password_confirm" in self.cleaned_data:
            if self.cleaned_data["password"] != self.cleaned_data["password_confirm"]:
                raise forms.ValidationError(_("You must type the same password each time."))
        return self.cleaned_data["password_confirm"]


class SettingsForm(forms.Form):
    email = forms.EmailField(label=_("Email"), required=True)
    timezone = forms.ChoiceField(
        label=_("Timezone"),
        choices=[("", "---------")] + settings.ACCOUNT_TIMEZONES,
        required=False
    )
    birthday = forms.DateField(widget=SelectDateWidget(years=range(1910, 2016)))

    if settings.USE_I18N:
        language = forms.ChoiceField(
            label=_("Language"),
            choices=settings.ACCOUNT_LANGUAGES,
            required=False
        )

    def clean_email(self):
        value = self.cleaned_data["email"]
        if self.initial.get("email") == value:
            return value
        qs = EmailAddress.objects.filter(email__iexact=value)
        if not qs.exists() or not settings.ACCOUNT_EMAIL_UNIQUE:
            return value
        raise forms.ValidationError(_("A user is registered with this email address."))


class GithubAuthForm(forms.Form):
    github_token = forms.CharField(max_length=255)


class GithubReposForm(forms.Form):  # need find an efficient and dynamic way to generate github repos
    def __init__(self, user, *args, **kwargs):
        super(GithubReposForm, self).__init__(*args, **kwargs)
        # get all repos related to the user
        repos_list = [repos_list for repos_list in GithubRepos.objects.filter(user=user)]
        i = 0
        for repos in repos_list:
            self.fields["repos%d" % i] = forms.CharField(label='', max_length=255, required=False,
                                                         initial=repos.repos_name,
                                                         widget=forms.TextInput(attrs={'readonly': 'readonly'}))
            repos_hook = GithubHooks.objects.get(github_repos=repos)
            self.fields["repos%d_hook" % i] = forms.BooleanField(label='Hooked', required=False,
                                                                 initial=repos_hook.repos_hook)
            # print(i, repos.repos_name, repos_hook.repos_hook)
            i += 1


def get_command_choices():
    """
    support ChoiceField choices dynamically
    """
    clone = ("clone", "Clone your hooked-repo from Github to local")
    pull = ("pull", "Pull down your hooked-repo from Github to local")
    push = ("push", "Push up your hooked-repo from local to Github")
    add = ("add", "Add localed changes")
    rm = ("rm", "Remove localed changes")
    commit = ("commit", "Commit changes")
    test = ("test", "Run test_opls.py in foyer")
    command_choice = (
        clone,
        pull,
        push,
        add,
        rm,
        commit,
        test,
    )
    # my_choice = git_choice
    return command_choice


class GithubHooksForm(forms.Form):
    def __init__(self, user, *args, **kwargs):
        super(GithubHooksForm, self).__init__(*args, **kwargs)
        hooks_list = [hooks_list for hooks_list in GithubHooks.objects.filter(github_repos__user=user)]
        final_choices = ()  # initial value
        repos_status = ""  # initial value
        repos_commit_sha = ""  # initial value
        repos_commit_time = ""  # initial value
        repos_commit_message = ""  # initial value
        i = 0
        for hooks in hooks_list:
            if hooks.repos_hook:
                hooks_choices = ("repos%d" % i, GithubRepos.objects.get(github_hooks=hooks).repos_name)
                final_choices = final_choices + (hooks_choices,)
                i += 1
        self.fields["github_hooked_repo"] = forms.ChoiceField(choices=final_choices, required=False)
        self.fields["github_hooked_command"] = forms.ChoiceField(choices=get_command_choices(), required=False)
        test_repos_name = Account.objects.get(user=user).test_repos_name
        if ReposStatus.objects.filter(github_repos__repos_name=test_repos_name).exists():
            repos_status = ReposStatus.objects.get(github_repos__repos_name=test_repos_name).repos_status
            repos_commit_sha = ReposStatus.objects.get(github_repos__repos_name=test_repos_name).repos_commit_sha
            repos_commit_time = ReposStatus.objects.get(github_repos__repos_name=test_repos_name).repos_commit_time
            repos_commit_message = ReposStatus.objects.get(
                github_repos__repos_name=test_repos_name).repos_commit_message
        self.fields["commit_sha"] = forms.CharField(required=False, initial=repos_commit_sha,
                                                      widget=forms.TextInput(attrs={'readonly': 'readonly'}))
        self.fields["commit_time"] = forms.CharField(required=False, initial=repos_commit_time,
                                                      widget=forms.TextInput(attrs={'readonly': 'readonly'}))
        self.fields["commit_message"] = forms.CharField(required=False, initial=repos_commit_message,
                                                      widget=forms.TextInput(attrs={'readonly': 'readonly'}))
        self.fields["repos_status"] = forms.CharField(required=False, initial=repos_status,
                                                      widget=forms.Textarea(attrs={'readonly': 'readonly'}))


class GithubHooksBackendForm(forms.Form):
    hooks_backend_get_response = forms.CharField(max_length=255)
