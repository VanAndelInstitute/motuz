import logging
import datetime
import time
from functools import wraps

from sqlalchemy.exc import IntegrityError
import flask_jwt_extended as flask_jwt
from ..models import RevokedToken
from ..application import db, jwt
from ..utils.pam import pam
from ..utils.groups import groups
from ..exceptions import *

# added claims and role support
# Zack Ramjan 2020-09-13
# see https://flask-jwt-extended.readthedocs.io/en/stable/tokens_from_complex_object/


class UserObject:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles

def refresh_token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            flask_jwt.verify_jwt_refresh_token_in_request()
        except Exception as e:
            raise HTTP_401_UNAUTHORIZED(str(e))

        return fn(*args, **kwargs)
    return wrapper



def token_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            flask_jwt.verify_jwt_in_request()
        except Exception as e:
            raise HTTP_401_UNAUTHORIZED(str(e))

        return fn(*args, **kwargs)
    return wrapper



@jwt.token_in_blacklist_loader
def _check_if_token_in_blacklist(token):
    """
    This function is automatically loaded and it does not need to be called.
    https://flask-jwt-extended.readthedocs.io/en/stable/blacklist_and_token_revoking/
    """
    return token_is_revoked(token)



@token_required
def get_logged_in_user(*args, **kwargs):
    return flask_jwt.get_jwt_identity()


#returns true if the user has a role the matches the admin role.
@token_required
def get_is_user_admin(*args, **kwargs):
    return  "hpcadmins" in flask_jwt.get_jwt_claims()['roles']


# Create a function that will be called whenever create_access_token
# is used. It will take whatever object is passed into the
# create_access_token method, and lets us define what custom claims
# should be added to the access token.
@jwt.user_claims_loader
def add_claims_to_access_token(user):
    return {'roles': user.roles}

# Create a function that will be called whenever create_access_token
# is used. It will take whatever object is passed into the
# create_access_token method, and lets us define what the identity
# of the access token should be.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.username


def login_user(data):
    username = data['username']
    password = data['password']

    user_authentication = pam()
    user_authentication.authenticate(username, password)

    if user_authentication.code != 0:
        logging.error("Could not authenticate {}. Reason: `{}` (Code: {})".format(
            username, user_authentication.reason, user_authentication.code,
        ))
        raise HTTP_401_UNAUTHORIZED('No match for Username and Password.')

    user_groups = groups()
    allUserGroups = user_groups.getGroups(username.split("@")[0])
    user = UserObject(username=username, roles=allUserGroups)

    return {
        'status': 'success',
        'message': 'Successfully logged in.',
        'access': flask_jwt.create_access_token(
            identity=user,
            expires_delta=datetime.timedelta(days=1),
        ),
        'refresh': flask_jwt.create_refresh_token(
            identity=user,
            expires_delta=datetime.timedelta(days=30),
        ),
    }



@refresh_token_required
def refresh_token():
    current_user = flask_jwt.get_jwt_identity()
    current_claims = flask_jwt.get_jwt_claims()['roles']
    user = UserObject(username=current_user, roles=current_claims)
    return {
        'status': 'success',
        'message': 'Successfully refreshed token.',
        'access': flask_jwt.create_access_token(
            identity=user,
            expires_delta=datetime.timedelta(days=1),
        ),
        'refresh': flask_jwt.create_refresh_token(
            identity = user,
            expires_delta=datetime.timedelta(days=30),
        ),
    }



@refresh_token_required
def logout_user():
    token = flask_jwt.get_raw_jwt()
    message = revoke_token(token)
    clean_token_database()
    return message



def revoke_token(token):
    try:
        revoked_token = RevokedToken(
            jti=token['jti'],
            type=token['type'],
            identity=token['identity'],
            exp=token['exp'],
        )
        db.session.add(revoked_token)
        db.session.commit()
        return {
            'status': 'success',
            'message': 'Successfully logged out.',
        }
    except IntegrityError as e:
        return {
            'status': 'fail',
            'message': 'Already logged out',
        }
    except Exception as e:
        return {
            'status': 'fail',
            'message': str(e),
        }



def token_is_revoked(token):
    """
    Check whether auth token has been blacklisted
    """
    if 'jti' not in token:
        return True

    res = RevokedToken.query.filter_by(jti=str(token['jti'])).first()
    if res:
        return True
    else:
        return False



def clean_token_database():
    now_ts = int(time.time())

    try:
        # Opting for this version for performance (single round-trip)
        query = RevokedToken.__table__.delete().where(RevokedToken.exp < now_ts)
        db.session.execute(query)
        db.session.commit()
    except Exception as e:
        logging.error("Could not clean up the token database")
        logging.exception(e)
