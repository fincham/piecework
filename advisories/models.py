import apt_pkg
apt_pkg.init_system()

from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone

from api.models import *

class Advisory(models.Model):
    """
    "Lowest common denominator" across all vendor advisories.
    """

    upstream_id = models.CharField(max_length=200, verbose_name="Upstream ID", help_text="The ID used by the vendor to refer to this advisory")
    short_description = models.CharField(max_length=200, null=True, help_text="One-line description of the advisory")
    description = models.TextField(null=True, help_text="Longer description of the advisory")
    action = models.TextField(null=True, help_text="What, if any, actions need to be taken to address the advisory")
    issued = models.DateTimeField(default=timezone.now, help_text="Date and time at which the advisory was issued")
    source = models.CharField(choices=settings.ADVISORY_SOURCES, max_length=32, help_text="Vendor source of the advisory")
    search_keywords = models.TextField(blank=True, null=True, help_text="Space separated list of keywords used to speed up search")

    class Meta:
        verbose_name_plural = "advisories"
        ordering = ["-issued"]

    def __str__(self):
        return self.upstream_id

    def get_absolute_url(self):
        from django.core.urlresolvers import reverse
        return reverse('advisory_detail', args=(self.upstream_id, ))

    def source_package_names(self):
        return ", ".join([package.__str__() for package in self.sourcepackage_set.all()])

    def vulnerability_names(self):
        return ", ".join([vulnerability.__str__() for vulnerability in self.vulnerabilities.all()])

    def source_url(self):
        return dict(settings.SOURCE_ADVISORY_DETAIL_URLS)[self.source] % self.upstream_id


class SourcePackage(models.Model):
    """
    Source package to which an advisory refers. These are not of a direct concern to hosts, as source packages are not actually "installed".

    For Debian advisories, the source package is used to determine what binary packages (and their versions) are considered safe.
    """

    advisory = models.ForeignKey(Advisory, help_text="Advisory to which this package belongs")
    package = models.CharField(max_length=200, help_text="Name of source package")
    release = models.CharField(choices=settings.RELEASES, max_length=32, help_text="Specific release to which this package belongs")
    safe_version = models.CharField(max_length=200, help_text="Package version that is to be considered 'safe' at the issue of this advisory")

    class Meta:
        verbose_name_plural = "source packages"
        ordering = ["-package"]

    def __str__(self):
        safe_version = self.safe_version

        if self.safe_version == '0':
            safe_version = ''

        return "%s %s (%s)" % (self.package, safe_version, self.release)

    def source_url(self):
        return dict(settings.SOURCE_PACKAGE_DETAIL_URLS)[self.advisory.source] % (self.release, self.package)

    def latest_advisory(self):
        all_advisories = {package.advisory_id for package in SourcePackage.objects.filter(package=self.package, release=self.release)}
        return Advisory.objects.filter(id__in=all_advisories).order_by('-issued')[0]

class BinaryPackage(models.Model):
    """
    Binary package to which an advisory refers.

    In the case of Ubuntu, these are resolved directly from the supplied JSON data. For Debian these will be generated based on the source packages
    associated with this advisory.

    If source_package is null it is because this binary package was created directly from external data, rather than being generated locally.
    """

    advisory = models.ForeignKey(Advisory, help_text="Advisory to which this package belongs")
    source_package = models.ForeignKey(SourcePackage, blank=True, null=True, help_text="If set, the source package from which this binary package was generated")
    package = models.CharField(max_length=200, help_text="Name of binary package")
    release = models.CharField(choices=settings.RELEASES, max_length=32, help_text="Specific release to which this package belongs")
    safe_version = models.CharField(max_length=200, null=True, help_text="Package version that is to be considered 'safe' at the issue of this advisory")
    architecture = models.CharField(max_length=200, null=True, help_text="Machine architecture")

    class Meta:
        verbose_name_plural = "binary packages"
        ordering = ["-package"]

    def __str__(self):
        if self.safe_version:
            return "%s %s (%s, %s)" % (self.package, self.safe_version, self.release, self.architecture)
        else:
            return "%s (%s, %s)" % (self.package, self.release, self.architecture)

    def source_url(self):
        return dict(settings.SOURCE_PACKAGE_DETAIL_URLS)[self.advisory.source] % (self.release, self.package)

class Vulnerability(models.Model):
    """
    CVE from the MITRE database to allow cross-referencing of advisories.
    """

    advisories = models.ManyToManyField(Advisory, related_name='vulnerabilities')
    first_seen = models.DateTimeField(default=timezone.now, help_text="Date and time at which the advisory was issued")
    upstream_id = models.CharField(max_length=200, help_text="MITRE name of CVE")

    class Meta:
        verbose_name_plural = "vulnerabilities"

    def __str__(self):
        return self.upstream_id

    def mitre_url(self):
        return "https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" % str(self)

    def source_list(self):
        return ", ".join(sorted([str(advisory).capitalize() for advisory in self.advisories.values_list('source', flat=True).distinct().order_by()]))

class Problem(models.Model):
    """
    Records the details around why a host is affected by an advisory.
    """

    advisory = models.ForeignKey(Advisory, help_text="Advisory that has caused this problem")
    host = models.ForeignKey(Host, help_text="Host which has the problem")
    installed_package_name = models.CharField(max_length=200, help_text="Name of binary package causing the problem", verbose_name='Package name')
    installed_package_version = models.CharField(max_length=200, help_text="Version of binary package causing the problem", verbose_name='Version')
    installed_package_architecture = models.CharField(max_length=200, help_text="Architecture of binary package causing the problem", verbose_name='Architecture')
    safe_package = models.ForeignKey(BinaryPackage, help_text="The safe package version provided by the advisory")
    created = models.DateTimeField(auto_now_add=True, verbose_name="Discovered")
    fixed = models.DateTimeField(null=True)
    fixed_by = models.CharField(null=True, choices=settings.FIX_REASONS, max_length=200, help_text="Way in which the problem was resolved")

    def __str__(self):
        return "%s: %s %s on %s" % (self.advisory, self.installed_package_name, self.installed_package_version, self.host)

    def is_fixed(self):
        return self.fixed is not None and timezone.now() >= self.fixed
    is_fixed.boolean = True

@receiver(post_save, sender=BinaryPackage)
def cache_applicable_hosts_for_advisory_package(sender, **kwargs):
    """
    When a new package is added to an advisory work out what hosts it applies to.
    """

    advisory_package = kwargs.get('instance')
    advisory = advisory_package.advisory
    print("Considering advisory package %s (%s)" % (advisory_package.package, advisory_package.architecture))
    affected_packages = Package.objects.filter(name=advisory_package.package, architecture=advisory_package.architecture, host__release=advisory_package.release)
    for package in affected_packages:
        unsafe = apt_pkg.version_compare(package.version, advisory_package.safe_version) < 0
        print("%s installed on %s is unsafe=%r due to installed version %s being <= %s" %(package.name, package.host, unsafe, package.version, advisory_package.safe_version))
        if unsafe:
            Problem.objects.get_or_create(advisory=advisory, host=package.host, installed_package_name=package.name, installed_package_version=package.version, installed_package_architecture=package.architecture, safe_package=advisory_package, fixed__isnull=True)
        else: # remove any problems that might have existed due to older incarnations of this advisory
            Problem.objects.filter(advisory=advisory, host=package.host, installed_package_name=package.name, installed_package_version=package.version, installed_package_architecture=package.architecture, safe_package=advisory_package).delete()

@receiver(post_save, sender=Package)
def add_package_to_host(sender, **kwargs):
    """
    When a package is added to a host find any advisories that apply to it and create problems.
    """

    package = kwargs.get('instance')
    print("installed %s on %s" % (package, package.host))
    advisory_packages = BinaryPackage.objects.filter(package=package.name, architecture=package.architecture, release=package.host.release)
    for advisory_package in advisory_packages:
        advisory = advisory_package.advisory
        unsafe = apt_pkg.version_compare(package.version, advisory_package.safe_version) < 0
        print("%s installed on %s is unsafe=%r due to installed version %s being <= %s" %(package.name, package.host, unsafe, package.version, advisory_package.safe_version))
        if unsafe:
            Problem.objects.get_or_create(advisory=advisory, host=package.host, installed_package_name=package.name, installed_package_version=package.version, installed_package_architecture=package.architecture, safe_package=advisory_package, fixed__isnull=True)

@receiver(pre_delete, sender=Package)
def remove_package_from_host(sender, **kwargs):
    """
    When a package is removed from a host find any problems removing it might solve.
    """

    package = kwargs.get('instance')
    print("removed %s from %s" % (package, package.host))
    Problem.objects.filter(host=package.host, installed_package_name=package.name, installed_package_version=package.version, installed_package_architecture=package.architecture).update(fixed=timezone.now(), fixed_by='removed')

