from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.core.exceptions import PermissionDenied, SuspiciousOperation, ObjectDoesNotExist
from django.views.decorators.http import require_http_methods
from django.utils.timezone import now
from django.db import transaction
from django.db.utils import IntegrityError
from django.utils.text import slugify

from .models import *

import json
import random
import string
import functools

def decode_json_body(fn):
    @functools.wraps(fn)
    def wrap(request, *args, **kwargs):
        try:
            form = json.loads(request.body.decode('utf-8'))
        except:
            response = {
                "node_invalid": True
            }
            return JsonResponse(response)
        return fn(request, form, *args, **kwargs)
    return wrap

def retrieve_host(fn):
    @functools.wraps(fn)
    def wrap(request, form, *args, **kwargs):
        try:
            host = Host.objects.get(node_key=form['node_key'])
            if host.invalidate:
                host.delete()
                raise ObjectDoesNotExist
            host.last_seen = now()
            host.save()
        except ObjectDoesNotExist:
            response = {
                "node_invalid": True
            }
            return JsonResponse(response)
        return fn(request, form, host, *args, **kwargs)
    return wrap

@decode_json_body
@csrf_exempt
@require_http_methods(['POST'])
def enroll(request, form):
    if form['enroll_secret'] == settings.OSQUERY_ENROLL_SECRET:
        rand = random.SystemRandom();
        node_key = "".join(rand.choice(string.hexdigits) for _ in range(32)).lower()
        response = {
            "node_key": node_key,
            "node_invalid": False
        }
        Host.objects.create(node_key=node_key, identifier=node_key, ram=0, cpu='', release='', architecture='')
    else:
        response = {
            "node_invalid": True
        }

    return JsonResponse(response)

@decode_json_body
@retrieve_host
@csrf_exempt
@require_http_methods(['POST'])
def config(request, form, host):
    response = {
        "schedule": {
            "hotplatehosts_os-version": {
                "query": "SELECT * FROM os_version;",
                "interval": 10
            },
            "hotplatehosts_system-info": {
                "query": "SELECT * FROM system_info;",
                "interval": 60,
                "snapshot": True
            },
            "hotplatehosts_deb-packages": {
                "query": "SELECT * FROM deb_packages;",
                "interval": 10
            },
            "hotplatehosts_osrelease": {
                "query": "select current_value from system_controls where name = 'kernel.osrelease';",
                "interval": 10
            },
        },
        "node_invalid": False
    }

    for query in LogQuery.objects.all():
       response['schedule']['hotplatehosts_db_%s' % slugify(query.name)] = {
           "query": "%s;" % query.query,
           "interval": query.interval
        }

    return JsonResponse(response)

@transaction.atomic
@decode_json_body
@retrieve_host
@csrf_exempt
@require_http_methods(['POST'])
def logger(request, form, host):
    if form['log_type'] == 'result': # a "change" on a query
        host.identifier = form['data'][0]['hostIdentifier']
        for submitted_log_entry in form['data']:
            entry_name = submitted_log_entry['name']
            entry_action = submitted_log_entry['action']
           
            recognised_action = False
            if entry_action == 'added':
                entry_output = submitted_log_entry['columns']
                if entry_name == "hotplatehosts_os-version":
                    host.release = entry_output['version'].split()[-1].strip('()')
                    recognised_action = True
                elif entry_name == "hotplatehosts_osrelease":
                    host.architecture = entry_output['current_value'].split('-')[-1]
                    recognised_action = True
                elif entry_name == "hotplatehosts_deb-packages":
                    with transaction.atomic():
                        try:
                            Package.objects.create(name=entry_output['name'], host=host, version=entry_output['version'], architecture=entry_output['arch'])
                        except IntegrityError: # ignore duplicates
                            continue
                    recognised_action = True
            
            elif entry_action == 'removed':
                entry_output = submitted_log_entry['columns']
                if entry_name == "hotplatehosts_deb-packages":
                    recognised_action = True
                    Package.objects.filter(name=entry_output['name'], host=host, version=entry_output['version'], architecture=entry_output['arch']).delete()
            
            elif entry_action == 'snapshot': # full snapshot query
                entry_outputs = submitted_log_entry['snapshot']
                for entry_output in entry_outputs:
                    if entry_name == "hotplatehosts_system-info":
                        host.cpu = entry_output['cpu_brand']
                        host.ram = int(entry_output['physical_memory'])
            
            if recognised_action == False and entry_action in ('added', 'removed') and entry_name.startswith('hotplatehosts_db_'): # just log in to the db
                    log_entry = LogEntry(name=entry_name[17:], action=entry_action, output=repr(entry_output), host=host)
                    log_entry.save()

    host.save()
    response = {
        "node_invalid": False
    }
    return JsonResponse(response)
