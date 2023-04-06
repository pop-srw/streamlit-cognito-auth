import pycognito
from pycognito import Cognito

from .exceptions import TokenVerificationException


def verify_access_token(pool_id, app_client_id, region, token):
    if not token:
        raise TokenVerificationException("Empty access token")

    u = Cognito(pool_id, app_client_id, user_pool_region=region)
    try:
        claims = u.verify_token(token, "access_token", "access")
        return claims
    except pycognito.exceptions.TokenVerificationException as e:
        print("error")
        raise TokenVerificationException(e)
