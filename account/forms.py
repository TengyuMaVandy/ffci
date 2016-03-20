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
from account.models import EmailAddress, Account
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
        widget=forms.TextInput(), required=True)

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

    """ ComboField doesn't work
    github_repos1 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(label='hook', required=False, initial=False)])
    github_repos2 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos3 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos4 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos5 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos6 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos7 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos8 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos9 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                       widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                             BooleanField(required=False, initial=False)])
    github_repos10 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos11 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos12 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos13 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos14 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos15 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos16 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos17 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos18 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos19 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    github_repos20 = forms.ComboField(fields=[CharField(label='', max_length=255, required=False,
                                                        widget=forms.TextInput(attrs={'readonly': 'readonly'})),
                                              BooleanField(required=False, initial=False)])
    """

    # """ try ComboField, doesn't work
    github_repos1 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos1_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos2 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos2_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos3 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos3_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos4 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos4_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos5 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos5_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos6 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos6_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos7 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos7_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos8 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos8_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos9 = forms.CharField(label='', max_length=255, required=False,
                                    widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos9_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos10 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos10_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos11 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos11_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos12 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos12_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos13 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos13_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos14 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos14_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos15 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos15_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos16 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos16_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos17 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos17_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos18 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos18_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos19 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos19_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    github_repos20 = forms.CharField(label='', max_length=255, required=False,
                                     widget=forms.TextInput(attrs={'readonly': 'readonly'}))
    github_repos20_hook = forms.BooleanField(label='Hooked', required=False, initial=False)
    # """


"""
support ChoiceField choices dynamically
"""


def get_command_choices():
    clone = ("clone", "Clone your hooked-repo from Github to local")
    pull = ("pull", "Pull down your hooked-repo from Github to local")
    push = ("push", "Push up your hooked-repo from local to Github")
    add = ("add", "Add localed changes")
    rm = ("rm", "Remove localed changes")
    commit = ("commit", "Commit changes")
    command_choice = (
        clone,
        pull,
        push,
        add,
        rm,
        commit,
    )
    # my_choice = git_choice
    return command_choice


class GithubHooksForm(forms.Form):
    def __init__(self, user, *args, **kwargs):
        super(GithubHooksForm, self).__init__(*args, **kwargs)
        hook1 = hook2 = hook3 = hook4 = hook5 = hook6 = hook7 = hook8 = hook9 = hook10 = \
            hook11 = hook12 = hook13 = hook14 = hook15 = hook16 = hook17 = hook18 = hook19 = hook20 = False
        repo1 = repo2 = repo3 = repo4 = repo5 = repo6 = repo7 = repo8 = repo9 = repo10 = \
            repo11 = repo12 = repo13 = repo14 = repo15 = repo16 = repo17 = repo18 = repo19 = repo20 = "No repo"
        hook1_choices = hook2_choices = hook3_choices = hook4_choices = hook5_choices = hook6_choices = \
            hook7_choices = hook8_choices = hook9_choices = hook10_choices = hook11_choices = hook12_choices = \
            hook13_choices = hook14_choices = hook15_choices = hook16_choices = hook17_choices = hook18_choices = \
            hook19_choices = hook20_choices = ("False", "No repo")
        for o in Account.objects.filter(user=user):
            hook1 = o.github_repos1_hook
            hook2 = o.github_repos2_hook
            hook3 = o.github_repos3_hook
            hook4 = o.github_repos4_hook
            hook5 = o.github_repos5_hook
            hook6 = o.github_repos6_hook
            hook7 = o.github_repos7_hook
            hook8 = o.github_repos8_hook
            hook9 = o.github_repos9_hook
            hook10 = o.github_repos10_hook
            hook11 = o.github_repos11_hook
            hook12 = o.github_repos12_hook
            hook13 = o.github_repos13_hook
            hook14 = o.github_repos14_hook
            hook15 = o.github_repos15_hook
            hook16 = o.github_repos16_hook
            hook17 = o.github_repos17_hook
            hook18 = o.github_repos18_hook
            hook19 = o.github_repos19_hook
            hook20 = o.github_repos20_hook
            repo1 = o.github_repos1
            repo2 = o.github_repos2
            repo3 = o.github_repos3
            repo4 = o.github_repos4
            repo5 = o.github_repos5
            repo6 = o.github_repos6
            repo7 = o.github_repos7
            repo8 = o.github_repos8
            repo9 = o.github_repos9
            repo10 = o.github_repos10
            repo11 = o.github_repos11
            repo12 = o.github_repos12
            repo13 = o.github_repos13
            repo14 = o.github_repos14
            repo15 = o.github_repos15
            repo16 = o.github_repos16
            repo17 = o.github_repos17
            repo18 = o.github_repos18
            repo19 = o.github_repos19
            repo20 = o.github_repos20
        final_choices = ()
        if hook1:
            hook1_choices = ("repo1", repo1)
            final_choices = final_choices + (hook1_choices,)
        if hook2:
            hook2_choices = ("repo2", repo2)
            final_choices = final_choices + (hook2_choices,)
        if hook3:
            hook3_choices = ("repo3", repo3)
            final_choices = final_choices + (hook3_choices,)
        if hook4:
            hook1_choices = ("repo4", repo4)
            final_choices = final_choices + (hook1_choices,)
        if hook5:
            hook2_choices = ("repo5", repo5)
            final_choices = final_choices + (hook2_choices,)
        if hook6:
            hook3_choices = ("repo6", repo6)
            final_choices = final_choices + (hook3_choices,)
        if hook7:
            hook1_choices = ("repo7", repo7)
            final_choices = final_choices + (hook1_choices,)
        if hook8:
            hook2_choices = ("repo8", repo8)
            final_choices = final_choices + (hook2_choices,)
        if hook9:
            hook3_choices = ("repo9", repo9)
            final_choices = final_choices + (hook3_choices,)
        if hook10:
            hook1_choices = ("repo10", repo10)
            final_choices = final_choices + (hook1_choices,)
        if hook11:
            hook2_choices = ("repo11", repo11)
            final_choices = final_choices + (hook2_choices,)
        if hook12:
            hook3_choices = ("repo12", repo12)
            final_choices = final_choices + (hook3_choices,)
        if hook13:
            hook1_choices = ("repo13", repo13)
            final_choices = final_choices + (hook1_choices,)
        if hook14:
            hook2_choices = ("repo14", repo14)
            final_choices = final_choices + (hook2_choices,)
        if hook15:
            hook3_choices = ("repo15", repo15)
            final_choices = final_choices + (hook3_choices,)
        if hook16:
            hook1_choices = ("repo16", repo16)
            final_choices = final_choices + (hook1_choices,)
        if hook17:
            hook2_choices = ("repo17", repo17)
            final_choices = final_choices + (hook2_choices,)
        if hook18:
            hook3_choices = ("repo18", repo18)
            final_choices = final_choices + (hook3_choices,)
        if hook19:
            hook1_choices = ("repo19", repo19)
            final_choices = final_choices + (hook1_choices,)
        if hook20:
            hook2_choices = ("repo20", repo20)
            final_choices = final_choices + (hook2_choices,)
        # print(final_choices)
        # final_choices = (
        #     hook1_choices,
        #     hook2_choices,
        #     hook3_choices,
        # )
        self.fields['github_hooked_repo'] = forms.ChoiceField(choices=final_choices, required=False)
        self.fields['github_hooked_command'] = forms.ChoiceField(choices=get_command_choices(), required=False)
        # [(o.github_repos1_hook, o.github_repos1) for o in Account.objects.filter(user=user)]

    # github_hooked_repo = forms.ChoiceField(choices=get_repo_choices())
    # github_hooks_command = forms.ChoiceField(choices=get_command_choices())


class GithubHooksBackendForm(forms.Form):
    hooks_backend_get_response = forms.CharField(max_length=255)
