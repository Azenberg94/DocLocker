"""
Definition of urls for DocLocker.
"""

from datetime import datetime
from django.conf.urls import url
import django.contrib.auth.views

import app.forms
import app.views

# Uncomment the next lines to enable the admin:
# from django.conf.urls import include
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = [
    # Examples:
    url(r'^$', app.views.home, name='home'),
    url(r'^home$', app.views.home, name='home'),
    url(r'^contact$', app.views.contact, name='contact'),
    url(r'^about', app.views.about, name='about'),
    url(r'^signup', app.views.signup, name='signup'),
    url(r'^uploadDoc', app.views.uploadDoc, name='uploadDoc'),
    url(r'^downloadDoc', app.views.downloadDoc, name='downloadDoc'),
    url(r'^login', app.views.login, name='login'),
    url(r'^logout', app.views.logout, name='logout'),
    url(r'^twoFactor', app.views.twoFactor, name='twoFactor'),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
]
