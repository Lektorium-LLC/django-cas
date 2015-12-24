"""CAS authentication middleware"""

from datetime import datetime
from urllib import urlencode

from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import login, logout
from django.core.urlresolvers import reverse

from django_cas.views import login as cas_login, logout as cas_logout, _service_url, instant_login, instant_login_url

__all__ = ['CASMiddleware']


class CASMiddleware(object):
    """Middleware that allows CAS authentication on admin pages"""

    def process_request(self, request):
        """Checks that the authentication middleware is installed"""

        error = ("The Django CAS middleware requires authentication "
                 "middleware to be installed. Edit your MIDDLEWARE_CLASSES "
                 "setting to insert 'django.contrib.auth.middleware."
                 "AuthenticationMiddleware'.")
        assert hasattr(request, 'user'), error

    def process_view(self, request, view_func, view_args, view_kwargs):
        """Forwards unauthenticated requests to the admin page to the CAS
        login URL, as well as calls to django.contrib.auth.views.login and
        logout.
        """

        if view_func == login:
            return cas_login(request, *view_args, **view_kwargs)
        elif view_func == logout:
            return cas_logout(request, *view_args, **view_kwargs)

        if settings.CAS_ADMIN_PREFIX:
            if not request.path.startswith(settings.CAS_ADMIN_PREFIX):
                return None
        elif not view_func.__module__.startswith('django.contrib.admin.'):
            return None

        if request.user.is_authenticated():
            if request.user.is_staff:
                return None
            else:
                error = ('<h1>Forbidden</h1><p>You do not have staff '
                         'privileges.</p>')
                return HttpResponseForbidden(error)
        params = urlencode({REDIRECT_FIELD_NAME: request.get_full_path()})
        return HttpResponseRedirect(reverse(cas_login) + '?' + params)


class CASInstantLoginMiddleware(object):
    """Allows instant login if user is already authenticated with CAS-server

    Requires CAS server to have gateway feature enabled"""

    SESSION_KEY = 'cas_instant_login_attempt'

    def process_view(self, request, view_func, view_args, view_kwargs):
        view_name = view_func.__module__ + '.' + view_func.__name__

        if (request.user.is_authenticated()
            or view_func in (cas_login, cas_logout, instant_login)
            or any(view_name.startswith(prefix)
                   for prefix in settings.CAS_INSTANT_LOGIN_EXEMPT)):
            return None

        last_login_attempt = request.session.get(self.SESSION_KEY, False)
        if (not last_login_attempt
            or not isinstance(last_login_attempt, datetime)
            or (datetime.now() - last_login_attempt).seconds > settings.CAS_INSTANT_LOGIN_TIMEOUT):

            request.session[self.SESSION_KEY] = datetime.now()
            return HttpResponseRedirect(instant_login_url(request))
