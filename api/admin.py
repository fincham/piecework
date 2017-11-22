from django.contrib import admin

from .models import *

class LogQueryAdmin(admin.ModelAdmin):
    list_display = ('name', 'query', 'interval')

class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('host', 'name', 'action', 'shortened_output', 'created')
    list_filter = ['created','action']

    def shortened_output(self, obj):
        if len(obj.output) > 90:
            return "%s..." % obj.output[:90]
        return obj.output

class PackageAdmin(admin.ModelAdmin):
    list_display = ('name', 'version', 'host', 'architecture', 'created')
    search_fields = ('name', )

class PackageInline(admin.TabularInline):
    model = Package

class LogEntryInline(admin.TabularInline):
    model = LogEntry
    extra = 0 

class HostAdmin(admin.ModelAdmin):
    list_display = ('identifier', 'release', 'architecture', 'cpu', 'ram_gib', 'last_seen', 'alive')
    inlines = [
        LogEntryInline,
    ]
    list_filter = ['release', 'architecture']

admin.site.register(Host, HostAdmin)
admin.site.register(LogEntry, LogEntryAdmin)
admin.site.register(LogQuery, LogQueryAdmin)
admin.site.register(Package, PackageAdmin)
