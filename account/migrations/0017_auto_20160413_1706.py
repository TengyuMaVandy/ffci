# -*- coding: utf-8 -*-
# Generated by Django 1.9.5 on 2016-04-13 22:06
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0016_auto_20160413_1649'),
    ]

    operations = [
        migrations.RenameField(
            model_name='account',
            old_name='test_repos',
            new_name='test_repos_name',
        ),
    ]
