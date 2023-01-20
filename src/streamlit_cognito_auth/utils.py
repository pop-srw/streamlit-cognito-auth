import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

from .exceptions import TokenVerificationException

# https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py
def verify_access_token(pool_id, app_client_id, region, token):
    if not token:
        raise TokenVerificationException("Empty access token")

    keys_url = (
        f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"
    )

    with urllib.request.urlopen(keys_url) as f:
        response = f.read()
    keys = json.loads(response.decode("utf-8"))["keys"]

    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers["kid"]
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]["kid"]:
            key_index = i
            break
    if key_index == -1:
        raise TokenVerificationException("Public key not found in jwks.json")

    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit(".", 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        raise TokenVerificationException("Signature verification failed")
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims["exp"]:
        raise TokenVerificationException("Token is expired")
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims["client_id"] != app_client_id:
        raise TokenVerificationException("Token was not issued for this client id")

    return claims
