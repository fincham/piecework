# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-18 03:48
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_logquery'),
    ]

    operations = [
        migrations.AlterField(
            model_name='host',
            name='architecture',
            field=models.CharField(blank=True, help_text='Machine architecture.', max_length=200),
        ),
        migrations.AlterField(
            model_name='host',
            name='cpu',
            field=models.CharField(blank=True, help_text='Model of CPU installed.', max_length=200),
        ),
        migrations.AlterField(
            model_name='host',
            name='ram',
            field=models.IntegerField(blank=True, help_text='Amount of RAM installed (KiB).'),
        ),
        migrations.AlterField(
            model_name='host',
            name='release',
            field=models.CharField(blank=True, help_text='Operating system release.', max_length=200),
        ),
    ]
