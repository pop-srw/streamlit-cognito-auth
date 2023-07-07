import os
import streamlit as st

from streamlit_cognito_auth import CognitoHostedUIAuthenticator

pool_id = os.environ["POOL_ID"]
app_client_id = os.environ["APP_CLIENT_ID"]
app_client_secret = os.environ["APP_CLIENT_SECRET"]
cognito_domain = os.environ["COGNITO_DOMAIN"]
redirect_uri = os.environ["REDIRECT_URI"]

authenticator = CognitoHostedUIAuthenticator(
    pool_id=pool_id,
    app_client_id=app_client_id,
    app_client_secret=app_client_secret,
    cognito_domain=cognito_domain,
    redirect_uri=redirect_uri,
    use_cookies=False
)

st.button("Hello")

is_logged_in = authenticator.login()
if not is_logged_in:
    st.stop()



def logout():
    print("Logout in example")
    authenticator.logout()


with st.sidebar:
    st.text(f"Welcome,\n{authenticator.get_username()}")
    st.button("Logout", "logout_btn", on_click=logout)

st.header("Hello world")
st.write("This is real app")
