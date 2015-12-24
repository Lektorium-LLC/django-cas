import urllib
import urlparse
from StringIO import StringIO
from mock import patch, mock_open
from time import sleep

from django.test import TestCase
from django.test.utils import override_settings
from django.test.client import Client
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME

from django_cas import views

SUCCESS_RESPONSE = '''\
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationSuccess>
        <cas:user>{0}</cas:user>
        <cas:attributes>
            <cas:attraStyle>Jasig</cas:attraStyle>
            <cas:uid>10193</cas:uid>
            <cas:mail>{0}@example.com</cas:mail>
            <cas:created>1409837178</cas:created>
            <cas:language>
            </cas:language>
            <cas:drupal_roles>authenticated user</cas:drupal_roles>
        </cas:attributes>
    </cas:authenticationSuccess>
</cas:serviceResponse>'''

FAILURE_RESPONSE = '''\
<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <cas:authenticationFailure code="INVALID_TICKET">
        Ticket ST-JWzceFvd8K not recognized.
    </cas:authenticationFailure>
</cas:serviceResponse>'''

def create_user(username, attributes):
    email = attributes.get('mail', '')
    return User.objects.create_user(username=username, email=email)

class CASLoginTest(TestCase):
    """
    Unit tests for django_cas authentication
    """
    def setUp(self):
        self.user = User.objects.create(username='test1', email='test1@example.com')
        self.client = Client()

    def tearDown(self):
        User.objects.all().delete()

    def test_login_redirect(self):
        response = self.client.get(reverse(views.login))
        self.assertEqual(response.status_code, 302)

    def test_login_success(self):
        with patch('urllib.urlopen', mock_open(read_data=SUCCESS_RESPONSE.format(self.user.username))):
            response = self.client.get(reverse('cas-login') + '?ticket=c3po')
            self.assertEqual(response.status_code, 302)
            self.assertIn('_auth_user_id', self.client.session)

    @patch('urllib.urlopen', mock_open(read_data=FAILURE_RESPONSE))
    def test_login_failure(self):
        response = self.client.get(reverse(views.login) + '?ticket=c3po')
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_user_created(self):
        username = 'test2'
        with patch('urllib.urlopen', mock_open(read_data=SUCCESS_RESPONSE.format(username))):
            response = self.client.get(reverse(views.login) + '?ticket=c3po')
            self.assertTrue(User.objects.filter(username=username).exists())
            self.assertIn('_auth_user_id', self.client.session)

    @override_settings(CAS_VERSION='3', CAS_USER_CREATOR=create_user)
    def test_user_creator(self):
        username = 'test3'
        with patch('urllib.urlopen', mock_open(read_data=SUCCESS_RESPONSE.format(username))):

            response = self.client.get(reverse(views.login) + '?ticket=c3po')
            self.assertTrue(User.objects.filter(username=username).exists())
            user = User.objects.get(username=username)
            self.assertEqual(user.email, '%s@example.com' % username)
            self.assertIn('_auth_user_id', self.client.session)


class CasInstantLoginMiddlewareTest(TestCase):
    '''
    Unit tests for instant login middleware
    '''

    def setUp(self):
        self.user = User.objects.create(username='test1', email='test1@example.com')
        self.user.set_password('password')
        self.user.save()
        self.client = Client()

    def tearDown(self):
        User.objects.all().delete()

    def test_user_authenticated(self):
        self.client.login(username=self.user.username, password='password')

        response = self.client.get('/')
        self.assertNotEqual(response.status_code, 302)

    def test_user_unauthenticated(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn(settings.CAS_SERVER_URL, response['Location'])
        self.assertIn(REDIRECT_FIELD_NAME, response['Location'])
        self.assertIn(urllib.quote(reverse(views.instant_login), safe=''), response['Location'])

    def test_repetitive_unauthenticated(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)

        response = self.client.get('/')
        self.assertNotEqual(response.status_code, 302)

    @override_settings(CAS_INSTANT_LOGIN_TIMEOUT=1)
    def test_instant_login_timeout(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)

        sleep(2)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertIn(settings.CAS_SERVER_URL, response['Location'])


class CasInstantLoginTest(TestCase):
    '''
    Unit tests for instant login view
    '''
    USERNAME = 'test1'

    def setUp(self):
        self.user = User.objects.create(username=self.USERNAME, email='test1@example.com')
        self.client = Client()

    def tearDown(self):
        User.objects.all().delete()

    def test_instant_login_success(self):
        with patch('urllib.urlopen', mock_open(read_data=SUCCESS_RESPONSE.format(self.USERNAME))) as mock_urlopen:
            response = self.client.get(reverse(views.instant_login) + '?ticket=c3po')
            self.assertEqual(response.status_code, 302)
            self.assertTrue(mock_urlopen.called)
            self.assertIn('_auth_user_id', self.client.session)

    @patch('urllib.urlopen', mock_open(read_data=FAILURE_RESPONSE))
    def test_instant_login_failure(self):
        response = self.client.get(reverse(views.instant_login) + '?ticket=c3po')
        self.assertEqual(response.status_code, 403)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_instant_login_created(self):
        username = 'test2'
        with patch('urllib.urlopen', mock_open(read_data=SUCCESS_RESPONSE.format(username))):
            response = self.client.get(reverse(views.instant_login) + '?ticket=c3po')
            self.assertTrue(User.objects.filter(username=username).exists())
            self.assertIn('_auth_user_id', self.client.session)

    def test_instant_login_no_ticket(self):
        # set flag in middleware to prevent repetivive redirects
        response = self.client.get('/')

        response = self.client.get(reverse(views.instant_login))
        self.assertEqual(response.status_code, 302)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertNotIn(settings.CAS_SERVER_URL, response['Location'])
        self.assertNotIn(REDIRECT_FIELD_NAME, response['Location'])

    def test_service_url(self):
        with patch('urllib.urlopen', mock_open(read_data=SUCCESS_RESPONSE.format(self.USERNAME))) as mock_urlopen:
            response = self.client.get('/?test=test_uuid')
            middleware_service_url = self._retrieve_url_param(response['Location'], 'service')

            response = self.client.get(reverse(views.instant_login)
                    + '?' + urllib.urlencode({'ticket':'c3po', REDIRECT_FIELD_NAME: '/?test=test_uuid'}))
            view_service_url = self._retrieve_url_param(mock_urlopen.call_args[0][0], 'service')

            self.assertEqual(middleware_service_url, view_service_url)
            self.assertIn('test_uuid', middleware_service_url[0])

    @staticmethod
    def _retrieve_url_param(url, param):
        parsed_url = urlparse.urlparse(url)
        query = urlparse.parse_qs(parsed_url.query)
        return query.get(param)
