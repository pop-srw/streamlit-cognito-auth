import os
import streamlit as st

from streamlit_cognito_auth import CognitoAuthenticator

pool_id = os.environ["POOL_ID"]
app_client_id = os.environ["APP_CLIENT_ID"]
app_client_secret = os.environ["APP_CLIENT_SECRET"]

authenticator = CognitoAuthenticator(
    pool_id=pool_id,
    app_client_id=app_client_id,
    app_client_secret=app_client_secret,
    use_cookies=False
)

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
