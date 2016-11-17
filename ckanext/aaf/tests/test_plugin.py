"""Tests for plugin.py."""
from datetime import datetime

import ckan.plugins
import jwt
from ckan import model
from ckan.lib.helpers import url_for
from ckan.tests import factories
from ckan.tests.helpers import FunctionalTestBase, _get_test_app
from mock import patch
from mock.mock import MagicMock
from mock.mock import Mock
from mock.mock import call
from nose.tools import assert_equal
from nose.tools import assert_raises
from pylons import config

import ckanext.aaf.controller
from ckanext.aaf import plugin
from ckanext.aaf.plugin import get_issuer


def get_token_payload(userid=None):
    if userid is None:
        userid = 'adefaultid'
    return {
        'https://aaf.edu.au/attributes': {
            'displayname': 'A user',
            'mail': 'email@example.com',
        },
        'sub': userid,
        'exp': datetime.utcnow(),
        'nbf': datetime.utcnow(),
        'iss': 'https://rapid.aaf.edu.au',
        'aud': config.get('ckanext.aaf.aud'),
        'iat': datetime.utcnow(),
    }


def get_test_token(userid=None):
    payload = get_token_payload(userid=userid)
    return jwt.encode(payload, config.get('ckanext.aaf.secret'))


class TestAAFController(FunctionalTestBase):
    '''
    Tests for the ckanext.example_iauthfunctions.plugin module.
    '''

    def __init__(self):
        self.app = None

    def setup(self):
        self.app = _get_test_app()
        ckan.plugins.load('aaf')

    @staticmethod
    def teardown():
        ckan.plugins.unload('aaf')

    def test_login_redirect(self):
        url = url_for(controller='ckanext.aaf.controller:AAFController', action='login', came_from='')
        res = self.app.get(url)
        assert_equal(res.location, config.get('ckanext.aaf.url'))

    def test_aaf_reply_tries_login(self):
        url = url_for(controller='ckanext.aaf.controller:AAFController', action='login', came_from='')
        token = get_test_token()
        # Skip the actual login
        with patch.object(ckanext.aaf.controller, 'login_with_token') as mock_login:
            self.app.post(url, params={'assertion': token})
        # Check our login got called with a valid decoded JWT token.
        expected = get_token_payload()
        assert_equal(len(mock_login.mock_calls), 1)
        mock_login_method, mock_login_args, mock_login_kwargs = mock_login.mock_calls[0]
        assert_equal(mock_login_method, '')
        assert_equal(mock_login_kwargs, {})
        assert_equal(len(mock_login_args), 1)
        for key, value in mock_login_args[0].items():
            # A decoded jwt token will have unix timestamps instead
            if isinstance(expected[key], datetime):
                # Microseconds and seconds get a bit of leeway (10 seconds)
                value = datetime.utcfromtimestamp(value).replace(
                    microsecond=expected[key].microsecond,
                    second=expected[key].second
                )
            assert_equal(expected[key], value, "key: {} --- {} != {}".format(key, expected[key], value))

    def test_token_decode(self):
        testuserid = 'theuseripassedin'
        token = get_test_token(userid=testuserid)
        request = Mock(POST={'assertion': token})
        verified_jwt = plugin.decode_token(request)
        assert_equal(verified_jwt['sub'], testuserid)

    def test_login_with_token_exists(self):
        testuserid = 'atestusertopassin'
        token = get_token_payload(userid=testuserid)

        def mock_get_action(*args, **kwargs):
            assert_equal(args, (), "Args were {}".format(args))
            assert_equal(kwargs, {
                'data_dict': {'q': testuserid},
                'context': {'ignore_auth': True}
            }, "Kwargs were {}".format(kwargs))
            return [{'name': testuserid, 'id': testuserid}]

        with patch.object(plugin, 'session') as mock_session:
            with patch.object(ckan.plugins.toolkit, 'redirect_to'):
                with patch.object(ckan.plugins.toolkit, 'get_action', return_value=mock_get_action):
                    plugin.login_with_token(token)

        expected = [
            call.__setitem__('aaf-user', testuserid),
            call.save()
        ]
        assert_equal(
            mock_session.mock_calls, expected,
            "{} != {}".format(mock_session.mock_calls, expected))

    def test_login_with_token_new(self):
        testuserid = 'atestusertopassin'
        token = get_token_payload(userid=testuserid)

        def mock_user_list(*args, **kwargs):
            assert_equal(args, ())
            assert_equal(kwargs, {
                'data_dict': {'q': testuserid},
                'context': {'ignore_auth': True}
            })
            return []

        def mock_user_create(*args, **kwargs):
            assert_equal(args, ())
            return {'name': testuserid, 'id': testuserid}

        def mock_get_action(action, data_dict=None):
            if action == 'user_list':
                return mock_user_list
            elif action == 'user_create':
                return mock_user_create

        with patch.object(plugin, 'session') as mock_session:
            with patch.object(ckan.plugins.toolkit, 'redirect_to'):
                with patch.object(ckan.plugins.toolkit, 'get_action', new=mock_get_action):
                    plugin.login_with_token(token)

        expected = [
            call.__setitem__('aaf-user', testuserid),
            call.save()
        ]
        assert_equal(mock_session.mock_calls, expected)

    def test_session_cleared(self):
        mock_session = MagicMock()
        mock_session.get.return_value = 'blah'
        aaf_attrs = ['aaf-user', 'aaf-blahblah']
        mock_session.__iter__.return_value = aaf_attrs
        with patch.object(plugin, 'session', new=mock_session):
            # session['aaf-user'] = 'test'
            url = url_for(controller='user', action='logout')
            self.app.get(url)

        expected = [
            call.get('aaf-user'),
            # Can't use nice call.__iter__() as that's one of the few methods that call has builtin.
            ('__iter__', (), {}),
        ]
        for attr in aaf_attrs:
            expected.append(call.__delitem__(attr))
        expected.append(call.save())

        print mock_session.mock_calls
        print expected
        assert_equal(mock_session.mock_calls, expected)

    def test_get_issuer_no_debug(self):
        assert_equal(get_issuer(), 'https://rapid.aaf.edu.au')

    def test_get_issuer_debug(self):
        old_val = config.get('ckanext.aaf.debug')
        config['ckanext.aaf.debug'] = True
        assert_equal(get_issuer(), 'https://rapid.test.aaf.edu.au')
        config['ckanext.aaf.debug'] = old_val

    def test_multiple_users_openid(self):
        testuserid = 'atestusertopassin'
        token = get_token_payload(userid=testuserid)

        def mock_get_action(*args, **kwargs):
            assert_equal(args, (), "Args were {}".format(args))
            assert_equal(kwargs, {'data_dict': {'q': testuserid}}, "Kwargs were {}".format(kwargs))
            return [{'name': testuserid}, {'name': 'a second one!'}]

        with patch.object(plugin, 'session') as mock_session:
            with patch.object(ckan.plugins.toolkit, 'redirect_to'):
                with patch.object(ckan.plugins.toolkit, 'get_action', return_value=mock_get_action):
                    assert_raises(Exception, plugin.login_with_token, token)

        assert_equal(mock_session.mock_calls, [])


class TestAAFAuth(FunctionalTestBase):
    def __init__(self):
        self.app = None
        self.user = None

    def setup(self):
        model.repo.rebuild_db()
        self.user = factories.User()
        self.app = _get_test_app()
        ckan.plugins.load('aaf')

    @staticmethod
    def teardown():
        ckan.plugins.unload('aaf')


class TestAAFAuthAllowCreationAlways(TestAAFAuth):
    @classmethod
    def _apply_config_changes(cls, cfg):
        cfg['ckan.auth.create_user_via_web'] = False
        cfg['ckanext.aaf.allow_creation_always'] = True

    def test_allow_creation_always(self):
        testuserid = 'atestusertopassin'

        token = get_test_token(userid=testuserid)

        url = url_for(controller='ckanext.aaf.controller:AAFController', action='login', came_from='')
        response = self.app.post(url, {'assertion': token})

        assert_equal(response.status_int, 302)
        response = response.follow()
        assert_equal(response.request.url, 'http://localhost/dashboard')


class TestAAFAuthAllowCreationFalse(TestAAFAuth):
    @classmethod
    def _apply_config_changes(cls, cfg):
        cfg['ckan.auth.create_user_via_web'] = False
        cfg['ckan.auth.create_user_via_api'] = False
        cfg['ckanext.aaf.allow_creation_always'] = False

    def test_allow_creation_always_false(self):
        testuserid = 'atestusertopassin'
        token = get_token_payload(userid=testuserid)

        print "always allow: {}, web creation: {}, api creation: {}".format(
            config.get('ckanext.aaf.allow_creation_always'
                       ),
            config.get('ckan.auth.create_user_via_web'),
            config.get('ckan.auth.create_user_via_api')
        )


        with patch.object(plugin, 'session') as mock_session:
            with patch.object(ckan.plugins.toolkit, 'redirect_to'):
                with patch.object(plugin.helpers, 'flash_error') as flash_mock:
                    plugin.login_with_token(token)

        assert_equal(flash_mock.mock_calls, [call('Not authorized to create users')])
