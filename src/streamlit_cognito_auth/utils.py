from typing import Dict, Any, Tuple

import pycognito # type: ignore
from pycognito import Cognito

from .exceptions import TokenVerificationException


def verify_access_token(pool_id, app_client_id, region, token) -> Tuple[Dict[str, Any], pycognito.UserObj]:
    if not token:
        raise TokenVerificationException("Empty access token")

    u = Cognito(pool_id, app_client_id, user_pool_region=region)
    try:
        claims = u.verify_token(token, "access_token", "access")
        user = u.get_user()
        return claims, user
    except pycognito.exceptions.TokenVerificationException as e:
        raise TokenVerificationException(e)
