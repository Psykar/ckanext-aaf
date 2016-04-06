import hashlib
import uuid

import ckan.plugins as p
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import jwt
from ckan.model.user import User
from pylons import config
from pylons import session


def decode_token(request):
    response = p.toolkit.response
    if config.get('debug'):
        issuer = 'https://rapid.test.aaf.edu.au'
    else:
        issuer = 'https://rapid.aaf.edu.au'

    options = {'require_exp': True, 'require_nbf': True, 'require_iat': True}
    try:
        verified_jwt = jwt.decode(
            request.POST['assertion'],
            config['ckanext.aaf.secret'],
            options=options,
            audience=config['ckanext.aaf.aud'],
            issuer=issuer,
        )
    except jwt.ExpiredSignature:
        response.status = 403
        response.response.write('Error: Security cookie has expired')
        return response

    return verified_jwt


def login_with_token(token):
    attributes = token['https://aaf.edu.au/attributes']
    user_unique_id = token['sub']
    try:
        user = User.by_openid(user_unique_id)
    except p.toolkit.ObjectNotFound:
        # Create the user.
        # The AAF id can contain invalid characters (for a ckan username)
        # So generate something safe and reasonably unlikely to collide
        # TODO (maybe use a uuid instead?)
        username = hashlib.md5(user_unique_id).hexdigest()
        user = p.toolkit.get_action('user_create')(
            context={'ignore_auth': True},
            data_dict={
                'name': username,
                'fullname': attributes['displayname'],
                'email': attributes['mail'],
                'password': str(uuid.uuid4()),
                # OpenID is a sensible place to put this even though it's not an OpenID, it's used
                # in a very similar way to an OpenID.
                'openid': user_unique_id
            }
        )
    if user:
        session['aaf-user'] = user.name
        session.save()
    p.toolkit.redirect_to(controller='user', action='dashboard')


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
