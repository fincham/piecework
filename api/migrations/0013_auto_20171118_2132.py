# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-18 08:32
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_auto_20171118_2041'),
    ]

    operations = [
        migrations.AlterField(
            model_name='logentry',
            name='output',
            field=models.TextField(),
        ),
    ]
