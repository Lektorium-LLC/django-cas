"""CAS login/logout replacement views"""
from datetime import datetime
from urllib import urlencode
from urlparse import urljoin
import logging

from django.http import HttpResponseRedirect, HttpResponseForbidden, HttpResponse
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django_cas.models import PgtIOU
from django.core.urlresolvers import reverse

__all__ = ['login', 'logout']

log = logging.getLogger("django-cas")


def _service_url(request, redirect_to=None, path_override=None):
    """Generates application service URL for CAS"""

    protocol = ('http://', 'https://')[request.is_secure()]
    host = request.get_host()
    service = protocol + host + (path_override or request.path)
    if redirect_to:
        if '?' in service:
            service += '&'
        else:
            service += '?'
        service += urlencode({REDIRECT_FIELD_NAME: redirect_to})
    return service


def _redirect_url(request):
    """Redirects to referring page, or CAS_REDIRECT_URL if no referrer is
    set.
    """

    next = request.GET.get(REDIRECT_FIELD_NAME)
    if not next:
        if settings.CAS_IGNORE_REFERER:
            next = settings.CAS_REDIRECT_URL
        else:
            next = request.META.get('HTTP_REFERER', settings.CAS_REDIRECT_URL)
        prefix = (('http://', 'https://')[request.is_secure()] +
                  request.get_host())
        if next.startswith(prefix):
            next = next[len(prefix):]
    return next


def _login_url(service, ticket='ST'):
    """Generates CAS login URL"""
    LOGINS = {'ST': 'login',
              'PT': 'proxyValidate'}
    params = {'service': service}
    if settings.CAS_EXTRA_LOGIN_PARAMS:
        params.update(settings.CAS_EXTRA_LOGIN_PARAMS)
    if not ticket:
        ticket = 'ST'
    login = LOGINS.get(ticket[:2], 'login')
    return urljoin(settings.CAS_SERVER_URL, login) + '?' + urlencode(params)


def instant_login_url(request):
    """Generates CAS gateway URL having instant login URL as 'service'
    and initial request path as 'next'"""

    next_page = request.get_full_path()
    params = {
        'service': _service_url(request, next_page, reverse(instant_login)),
        'gateway': 'true'
    }
    if settings.CAS_EXTRA_LOGIN_PARAMS:
        params.update(settings.CAS_EXTRA_LOGIN_PARAMS)
    return urljoin(settings.CAS_SERVER_URL, 'login') + '?' + urlencode(params)


def _logout_url(request, next_page=None):
    """Generates CAS logout URL"""

    url = urljoin(settings.CAS_SERVER_URL, 'logout')
    if next_page:
        protocol = ('http://', 'https://')[request.is_secure()]
        host = request.get_host()
        url += '?' + urlencode({'url': protocol + host + next_page})
    return url


def instant_login(request, next_page=None):
    """Handles response from CAS-server working as 'gateway'"""

    next_page = request.GET.get(REDIRECT_FIELD_NAME, settings.CAS_REDIRECT_URL)
    if request.GET.get('ticket'):
        return login(request, next_page)
    else:
        return HttpResponseRedirect(next_page)


def login(request, next_page=None, required=False):
    """Forwards to CAS login URL or verifies CAS ticket"""

    if not next_page:
        next_page = _redirect_url(request)
    if request.user.is_authenticated():
        return HttpResponseRedirect(next_page)
    ticket = request.GET.get('ticket')
    service = _service_url(request, next_page)
    if ticket:
        from django.contrib import auth
        user = auth.authenticate(ticket=ticket, service=service)

        if user is not None:
            auth.login(request, user)
            name = user.first_name or user.username
            return HttpResponseRedirect(next_page)
        elif settings.CAS_RETRY_LOGIN or required:
            log.error('CAS authentication with ticket {} failed, retrying'.format(ticket))
            return HttpResponseRedirect(_login_url(service, ticket))
        else:
            log.error('CAS authentication with ticket {} failed'.format(ticket))
            error = "<h1>Forbidden</h1><p>Login failed.</p>"
            return HttpResponseForbidden(error)
    else:
        return HttpResponseRedirect(_login_url(service, ticket))


def logout(request, next_page=None):
    """Redirects to CAS logout page"""

    from django.contrib.auth import logout
    logout(request)
    if not next_page:
        next_page = _redirect_url(request)
    if settings.CAS_LOGOUT_COMPLETELY:
        return HttpResponseRedirect(_logout_url(request, next_page))
    else:
        return HttpResponseRedirect(next_page)


def proxy_callback(request):
    """Handles CAS 2.0+ XML-based proxy callback call.
    Stores the proxy granting ticket in the database for
    future use.

    NB: Use created and set it in python in case database
    has issues with setting up the default timestamp value
    """
    pgtIou = request.GET.get('pgtIou')
    tgt = request.GET.get('pgtId')

    if not (pgtIou and tgt):
        return HttpResponse()

    try:
        PgtIOU.objects.create(tgt=tgt, pgtIou=pgtIou, created=datetime.now())
    except:
        return HttpResponse('PGT storage failed for %s' % str(request.GET), mimetype="text/plain")

    return HttpResponse('Success', mimetype="text/plain")
