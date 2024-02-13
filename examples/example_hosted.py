import os
import streamlit as st
import boto3

from streamlit_cognito_auth import CognitoHostedUIAuthenticator
from streamlit_cognito_auth.session_provider import Boto3SessionProvider

pool_id = os.environ["COGNITO_USER_POOL_ID"]
app_client_id = os.environ["COGNITO_APP_CLIENT_ID"]
app_client_secret = os.environ["COGNITO_APP_CLIENT_SECRET"]
cognito_domain = os.environ["COGNITO_DOMAIN"]
redirect_uri = os.environ["COGNITO_REDIRECT_URI"]
region = os.environ["AWS_REGION"]
identity_pool_id = os.environ["COGNITO_IDENTITY_POOL_ID"]
aws_account_id = os.environ["AWS_ACCOUNT_ID"]

authenticator = CognitoHostedUIAuthenticator(
    pool_id=pool_id,
    app_client_id=app_client_id,
    app_client_secret=app_client_secret,
    cognito_domain=cognito_domain,
    redirect_uri=redirect_uri,
    use_cookies=False
)

session_provider = Boto3SessionProvider(
    region=region,
    account_id=aws_account_id,
    user_pool_id=pool_id,
    identity_pool_id=identity_pool_id,
)


is_logged_in = authenticator.login()
if not is_logged_in:
    st.stop()



def logout():
    print("Logout in example")
    authenticator.logout()


with st.sidebar:
    st.text(f"Welcome,\n{authenticator.get_username()}")
    st.text(f"Your email is:\n{authenticator.get_email()}")
    st.button("Logout", "logout_btn", on_click=logout)

st.header("Hello world")
st.write("This is real app")

credentials = authenticator.get_credentials()
if not credentials:
    st.stop()

session_provider.setup_default_session(credentials.id_token, region_name=region)

# Test the session with any AWS service
st.subheader("Successfully assumed the following AWS role")
sts = boto3.client("sts")
response = sts.get_caller_identity()
response.pop("ResponseMetadata")
st.write(response)
