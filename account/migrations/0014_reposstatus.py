# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-04-13 17:59
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0013_auto_20160324_1734'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReposStatus',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('repos_status', models.TextField(null=True)),
                ('github_repos', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='repos_status', to='account.GithubRepos', verbose_name='github_repos')),
            ],
        ),
    ]