import re
import uuid

import ckan.lib.helpers as helpers
import ckan.logic as logic
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import jwt
from paste.deploy.converters import asbool
from pylons import config
from pylons import session


def get_issuer():
    if asbool(config.get('ckanext.aaf.debug')):
        issuer = 'https://rapid.test.aaf.edu.au'
    else:
        issuer = 'https://rapid.aaf.edu.au'
    return issuer


def decode_token(request):
    issuer = get_issuer()

    options = {'require_exp': True, 'require_nbf': True, 'require_iat': True}
    verified_jwt = jwt.decode(
        request.POST['assertion'],
        config['ckanext.aaf.secret'],
        options=options,
        audience=config['ckanext.aaf.aud'],
        issuer=issuer,
        # Leeway of 10 seconds with tokens to account for time skew
        leeway=10
    )

    return verified_jwt


def login_with_token(token):
    attributes = token['https://aaf.edu.au/attributes']
    user_unique_id = token['sub']
    users = toolkit.get_action('user_list')(data_dict=dict(q=user_unique_id), context={'ignore_auth': True})

    if len(users) == 1:
        user = users[0]
    elif len(users) == 0:
        # Create the user.
        # The AAF id can contain invalid characters (for a ckan username)
        # So generate something safe and reasonably unlikely to collide
        username = '{}_aaf'.format(re.sub('[\W]+', '_', attributes['mail']))
        user_create = toolkit.get_action('user_create')
        data_dict = {
            'name': username,
            'fullname': attributes['displayname'],
            'email': attributes['mail'],
            # Just give a random password
            'password': str(uuid.uuid4()),
            # OpenID is a sensible place to put this even though it's not an OpenID, it's used
            # in a very similar way to an OpenID.
            'openid': user_unique_id
        }
        if asbool(config.get('ckanext.aaf.allow_creation_always')):
            user = user_create(context={'ignore_auth': True}, data_dict=data_dict)
        else:
            try:
                user = user_create(context=None, data_dict=data_dict)
            except logic.NotAuthorized as e:
                helpers.flash_error(e.message)
                return toolkit.redirect_to(controller='home', action='index')
    else:
        raise Exception("Found invalid number of users with this AAF ID {}".format(user_unique_id))

    session['aaf-user'] = user['name']
    session.save()
    return toolkit.redirect_to(controller='user', action='dashboard')


class AafPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes, inherit=True)
    plugins.implements(plugins.IAuthenticator, inherit=True)

    # IConfigurer

    @staticmethod
    def update_config(config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'aaf')

    # IRoutes

    @staticmethod
    def before_map(map):
        controller = 'ckanext.aaf.controller:AAFController'
        map.connect('aaf',
                    '/aaf/login',
                    controller=controller,
                    action='login')
        return map

    @staticmethod
    def identify():
        user = session.get('aaf-user')
        if user:
            toolkit.c.user = user

    @staticmethod
    def logout():
        keys_to_delete = [key for key in session
                          if key.startswith('aaf-')]
        if keys_to_delete:
            for key in keys_to_delete:
                del session[key]
            session.save()
