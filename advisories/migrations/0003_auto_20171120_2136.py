# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-20 08:36
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_auto_20171120_2119'),
        ('advisories', '0002_vulnerability'),
    ]

    operations = [
        migrations.CreateModel(
            name='Problem',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('installed_package_name', models.CharField(help_text='Name of binary package causing the problem', max_length=200, verbose_name='Package name')),
                ('installed_package_version', models.CharField(help_text='Version of binary package causing the problem', max_length=200, verbose_name='Version')),
                ('installed_package_architecture', models.CharField(help_text='Architecture of binary package causing the problem', max_length=200, verbose_name='Architecture')),
                ('created', models.DateTimeField(auto_now_add=True, verbose_name='Discovered')),
                ('fixed', models.DateTimeField(null=True)),
                ('fixed_by', models.CharField(choices=[('removed', 'Package removed')], help_text='Way in which the problem was resolved', max_length=200, null=True)),
                ('advisory', models.ForeignKey(help_text='Advisory that has caused this problem', on_delete=django.db.models.deletion.CASCADE, to='advisories.Advisory')),
                ('host', models.ForeignKey(help_text='Host which has the problem', on_delete=django.db.models.deletion.CASCADE, to='api.Host')),
                ('safe_package', models.ForeignKey(help_text='The safe package version provided by the advisory', on_delete=django.db.models.deletion.CASCADE, to='advisories.BinaryPackage')),
            ],
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='advisories',
            field=models.ManyToManyField(related_name='vulnerabilities', to='advisories.Advisory'),
        ),
    ]
