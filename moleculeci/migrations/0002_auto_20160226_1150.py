# -*- coding: utf-8 -*-
# Generated by Django 1.9.2 on 2016-02-26 17:50
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('moleculeci', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='birthdate',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='git_name',
            field=models.CharField(default='git_name', max_length=255),
        ),
    ]