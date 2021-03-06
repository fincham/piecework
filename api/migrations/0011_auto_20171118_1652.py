# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-18 03:52
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_auto_20171118_1649'),
    ]

    operations = [
        migrations.AlterField(
            model_name='host',
            name='architecture',
            field=models.CharField(blank=True, db_index=True, help_text='Machine architecture.', max_length=200),
        ),
        migrations.AlterField(
            model_name='host',
            name='identifier',
            field=models.CharField(db_index=True, help_text='Unique identifier for this system (usually hostname).', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='host',
            name='node_key',
            field=models.CharField(db_index=True, help_text='Secret key this host uses to identify itself.', max_length=32, unique=True),
        ),
        migrations.AlterField(
            model_name='host',
            name='release',
            field=models.CharField(blank=True, db_index=True, help_text='Operating system release.', max_length=200),
        ),
        migrations.AlterField(
            model_name='logentry',
            name='name',
            field=models.CharField(db_index=True, max_length=255),
        ),
    ]
