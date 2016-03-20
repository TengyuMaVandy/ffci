#!/usr/bin/env python
# import account.views
# from django.contrib.auth import get_user_model
#
# from .models import UserProfile
# from .forms import SignupForm
#
#
# class SignupView(account.views.SignupView):
#     form_class = SignupForm
#
#     def generate_username(self, form):
#         super(SignupView, self).generate_username(form)
#
#     def after_signup(self, form):
#         self.update_profile(form)
        # super(SignupView, self).after_signup(form)

    # def update_profile(self, form):
        # UserProfile.objects.create(
        #     user=self.created_user,
        #     github_name=form.cleaned_data["github_name"],
        # )
        # self.created_user = self.create_user(form)
        # profile = self.created_user.profile
        # profile.some_attr = "some value"
        # profile.birthdate = form.cleaned_data["birthdate"]
        # profile.birthdate = form.cleaned_data["birthdate"]
        # self.created_user.save()

    # def create_user(self, form, commit=True, model=None, **kwargs):
    #     user = super(SignupView, self).create_user(form, commit=False)
    #
    #     return user


# class SettingsView(account.views.SettingsView):
#     form_class = SettingsForm
    # github_name = GithubInfo.objects.get(github_name=github_name)
    # repo_name = GithubInfo.repo_name
    # repo_path = GithubInfo.repo_path
    # key = GithubInfo.key
    # git_cmd = GithubInfo.git_cmd
