"""Tests for plugin.py."""
from datetime import datetime

import ckan.plugins
import jwt
from ckan.lib.helpers import url_for
from ckan.model.user import User
from ckan.tests.helpers import FunctionalTestBase, _get_test_app
from mock.mock import Mock
from mock.mock import MagicMock
from mock.mock import call
from mock import patch
from pylons import config
from pylons import session

from ckanext.aaf import plugin
from ckanext.aaf.plugin import get_issuer
import ckanext.aaf.controller


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

    @staticmethod
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

    def get_test_token(self, userid=None):
        payload = self.get_token_payload(userid=userid)
        return jwt.encode(payload, config.get('ckanext.aaf.secret'))

    def test_login_redirect(self):
        url = url_for(controller='ckanext.aaf.controller:AAFController', action='login', came_from='')
        res = self.app.get(url)
        assert(res.location == config.get('ckanext.aaf.url'))

    def test_aaf_reply_tries_login(self):
        url = url_for(controller='ckanext.aaf.controller:AAFController', action='login', came_from='')
        token = self.get_test_token()
        # Skip the actual login
        with patch.object(ckanext.aaf.controller, 'login_with_token') as mock_login:
            self.app.post(url, params={'assertion': token})
        # Check our login got called with a valid decoded JWT token.
        expected = self.get_token_payload()
        assert(len(mock_login.mock_calls) == 1)
        mock_login_method, mock_login_args, mock_login_kwargs = mock_login.mock_calls[0]
        assert(mock_login_method == '')
        assert(mock_login_kwargs == {})
        assert(len(mock_login_args) == 1)
        for key, value in mock_login_args[0].items():
            # A decoded jwt token will have unix timestamps instead
            if isinstance(expected[key], datetime):
                value = datetime.utcfromtimestamp(value).replace(microsecond=expected[key].microsecond)
            assert(expected[key] == value)

    def test_token_decode(self):
        testuserid = 'theuseripassedin'
        token = self.get_test_token(userid=testuserid)
        request = Mock(POST={'assertion': token})
        print(request.POST['assertion'])
        verified_jwt = plugin.decode_token(request)
        assert(verified_jwt['sub'] == testuserid)

    def test_login_with_token_exists(self):
        testuserid = 'atestusertopassin'
        token = self.get_token_payload(userid=testuserid)

        mock_user = Mock(name=testuserid)
        with patch.object(plugin, 'session') as mock_session:
            with patch.object(ckan.plugins.toolkit, 'redirect_to'):

                with patch.object(User, 'by_openid', return_value=mock_user):
                    plugin.login_with_token(token)

        expected = [
            call.__setitem__('aaf-user', mock_user.name),
            call.save()
        ]
        assert(mock_session.mock_calls == expected)

    def test_login_with_token_new(self):
        testuserid = 'atestusertopassin'
        token = self.get_token_payload(userid=testuserid)

        mock_user = Mock(name=testuserid)

        def tookkit_create_mock(context=None, data_dict=None):
            return mock_user

        with patch.object(plugin, 'session') as mock_session:
            with patch.object(ckan.plugins.toolkit, 'redirect_to'):
                with patch.object(User, 'by_openid', side_effect=ckan.plugins.toolkit.ObjectNotFound):
                    with patch.object(ckan.plugins.toolkit, 'get_action', return_value=tookkit_create_mock):
                        plugin.login_with_token(token)


        expected = [
            call.__setitem__('aaf-user', mock_user.name),
            call.save()
        ]
        assert(mock_session.mock_calls == expected)

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
        assert(mock_session.mock_calls == expected)

    def test_get_issuer_no_debug(self):
        assert get_issuer() == 'https://rapid.aaf.edu.au'

    def test_get_issuer_debug(self):
        old_val = config.get('debug')
        config['debug'] = True
        assert(get_issuer() == 'https://rapid.test.aaf.edu.au')
        config['debug'] =  old_val