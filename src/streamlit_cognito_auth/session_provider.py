from typing import Dict, Any, Callable, Optional

import boto3
import botocore.session, botocore.credentials



class Boto3SessionProvider:
    """This class creates boto3 Session objects that authenticate boto3 calls with the cognito
    identity.

    Args:
        region: The AWS region of the Cognito user pool
        account_id: The AWS account ID of the Cognito user pool
        user_pool_id: The Cognito user pool ID
        identity_pool_id: The Cognito identity pool ID
        refresh_callback: If specified, this callback will be called when the credentials are to
            expire. You are expected to return a fresh id_token from this callback.
    """

    region: str
    account_id: str
    user_pool_id: str
    identity_pool_id: str
    refresh_callback: Optional[Callable[[], str]] = None

    def __init__(self,
        region: str,
        account_id: str,
        user_pool_id: str,
        identity_pool_id: str,
        refresh_callback: Optional[Callable[[], str]] = None,
    ) -> None:
        self.cognito_client = boto3.client("cognito-identity", region_name=region)
        self.region = region
        self.account_id = account_id
        self.user_pool_id = user_pool_id
        self.identity_pool_id = identity_pool_id
        self.refresh_callback = refresh_callback

    def _get_cognito_login_descriptor(self, id_token: str) -> Dict[str, str]:
        return {
            f"cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}": id_token
        }

    def _get_identity_id(self, id_token: str) -> str:
        response = self.cognito_client.get_id(
            AccountId=self.account_id,
            IdentityPoolId=self.identity_pool_id,
            Logins=self._get_cognito_login_descriptor(id_token)
        )
        return response["IdentityId"]

    def _get_aws_credentials(self,
        identity_id: str,
        id_token: str
    ) -> Dict[str, Any]:
        response = self.cognito_client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins=self._get_cognito_login_descriptor(id_token)
        )
        return response["Credentials"]

    def _get_credentials(self, id_token: str) -> botocore.credentials.Credentials:
        identity_id = self._get_identity_id(id_token)
        aws_credentials = self._get_aws_credentials(identity_id, id_token)
        kwargs = {
            "access_key": aws_credentials["AccessKeyId"],
            "secret_key": aws_credentials["SecretKey"],
            "token": aws_credentials["SessionToken"],
            "method": "custom_cognito_auth",
        }
        credentials = botocore.credentials.RefreshableCredentials(
            **kwargs,
            expiry_time=aws_credentials["Expiration"],
            refresh_using=lambda: self._get_credentials(self.refresh_callback()),
        ) if self.refresh_callback is not None else botocore.credentials.Credentials(**kwargs)
        return credentials

    def _get_botocore_session(self, id_token: str) -> botocore.session.Session:
        botocore_session = botocore.session.get_session()
        credentials = self._get_credentials(id_token)
        setattr(botocore_session, "_credentials", credentials)
        return botocore_session

    def get_session(self, id_token: str, **kwargs) -> boto3.Session:
        """Get a boto3 session, configured with the Cognito credentials.

        Args:
            id_token: The identity token of the Cognito identity
            **kwargs: Keyword arguments to be passed to boto3.Session initializer
        """
        botocore_session = self._get_botocore_session(id_token=id_token)
        return boto3.Session(botocore_session=botocore_session, **kwargs)

    def setup_default_session(self, id_token: str, **kwargs) -> None:
        """Sets up the default boto3 session with Cognito credentials.

        The default session will be used by boto3.client() and boto3.resource() calls.
        Args:
            id_token: The identity token of the Cognito identity
            **kwargs: Keyword arguments to be passed to boto3.Session initializer
        """
        botocore_session = self._get_botocore_session(id_token=id_token)
        boto3.setup_default_session(botocore_session=botocore_session, **kwargs)