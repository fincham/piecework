from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^enroll$', views.enroll, name='enroll'),
    url(r'^config$', views.config, name='config'),
    url(r'^logger$', views.logger, name='logger'),
]

