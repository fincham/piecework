from django.db import models
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone

import math
import datetime

class Host(models.Model):
    """
    One computer
    """

    node_key = models.CharField(max_length=32, db_index=True, unique=True, help_text="Secret key this host uses to identify itself.")
    identifier = models.CharField(max_length=255, db_index=True, help_text="Unique identifier for this system (usually hostname).")
    last_seen = models.DateTimeField(auto_now_add=True, help_text="Last time this host checked in.")
    invalidate = models.BooleanField(default=False, help_text="Whether this node should be re-enrolled from scratch next time it checks in.")
    architecture = models.CharField(max_length=200, db_index=True, help_text="Machine architecture.", blank=True)
    release = models.CharField(max_length=200, db_index=True, help_text="Operating system release.", blank=True)
    cpu = models.CharField(max_length=200, help_text="Model of CPU installed.", blank=True)
    ram = models.BigIntegerField(help_text="Amount of RAM installed (KiB).", blank=True)

    def __str__(self):
        if self.identifier:
            return self.identifier
        return self.node_key

    def ram_gib(self):
        return math.ceil(self.ram / 1024 / 1024 / 1024)

    def alive(self):
        return self.last_seen > timezone.now() - datetime.timedelta(minutes=30)
    alive.boolean = True

class Package(models.Model):
    """
    Operating system package
    """

    name = models.CharField(db_index=True, max_length=200, help_text="Name of package from the operating system's package manager.")
    host = models.ForeignKey(Host, db_index=True)
    version = models.CharField(db_index=True, max_length=200, help_text="The package manager's version for this package.")
    architecture = models.CharField(max_length=200, help_text="Package architecture, which may differ from the host architecture.")
    created = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("name", "host", "architecture"),)

    def __unicode__(self):
        return "%s" % self.name

class LogQuery(models.Model):
    """
    Query to be run on all hosts.
    """

    name = models.CharField(max_length=255, help_text="A descriptive name for the query")
    query = models.CharField(max_length=255, help_text="The query to be executed")
    interval = models.IntegerField(help_text="How often should the query be run (in seconds)?", default=10)

    class Meta:
        verbose_name_plural = "log queries"

    def __str__(self):
        return self.name

class LogEntry(models.Model):
    """
    Logged query result.
    """

    name = models.CharField(max_length=255, db_index=True)
    action = models.CharField(max_length=255)
    output = models.TextField()
    created = models.DateTimeField(auto_now_add=True)
    host = models.ForeignKey(Host, db_index=True, on_delete=models.CASCADE)

    class Meta:
        verbose_name_plural = "log entries"

    def __str__(self):
        return "%s %s on %s" % (self.name, self.action, str(self.host))

