import ckan.controllers.user as user
import ckan.plugins as p
from pylons import config

from plugin import decode_token
from plugin import login_with_token


class AAFController(user.UserController):
    def login(self, error=None):
        # Either send a request off to AAF, or handle a POST response from AAF
        request = p.toolkit.request
        if request.method != 'POST':
            p.toolkit.redirect_to(config['ckanext.aaf.url'])
        else:
            token = decode_token(request)
            login_with_token(token)
