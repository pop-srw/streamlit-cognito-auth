import time
import boto3

from warrant import AWSSRP
import streamlit as st
import extra_streamlit_components as stx

from .exceptions import TokenVerificationException
from .utils import verify_access_token


class CognitoAuthenticator:
    def __init__(self, pool_id, app_client_id, app_client_secret, boto_client=None):
        self.client = boto_client or boto3.client("cognito-idp")
        self.pool_id = pool_id
        self.pool_region = pool_id.split("_")[0]
        self.app_client_id = app_client_id
        self.app_client_secret = app_client_secret

        self.cookie_manager = stx.CookieManager()

    def _load_session_state_from_cookies(self):
        st.session_state["auth_access_token"] = self.cookie_manager.get("access_token")
        st.session_state["auth_id_token"] = self.cookie_manager.get("id_token")
        st.session_state["auth_refresh_token"] = self.cookie_manager.get(
            "refresh_token"
        )

        try:
            claims = verify_access_token(
                self.pool_id,
                self.app_client_id,
                self.pool_region,
                st.session_state["auth_access_token"],
            )
            # later, refresh token here
            if not claims:
                raise TokenVerificationException("No returned claims")

            st.session_state["auth_state"] = "logged_in"
            st.session_state["auth_username"] = claims["username"]
            st.session_state["auth_expires"] = claims["exp"]

        except TokenVerificationException:
            st.session_state["auth_state"] = "logged_out"
            st.session_state["auth_username"] = ""
            st.session_state["auth_expires"] = 0

    def _clear_cookies(self):
        self.cookie_manager.delete("access_token", key="delete_access_token")
        self.cookie_manager.delete("id_token", key="delete_id_token")
        self.cookie_manager.delete("refresh_token", key="delete_refresh_token")

    def _reset_session_state(self):
        st.session_state["auth_state"] = "logged_out"

        st.session_state["auth_access_token"] = ""
        st.session_state["auth_id_token"] = ""
        st.session_state["auth_refresh_token"] = ""

        st.session_state["auth_expires"] = 0
        st.session_state["auth_username"] = ""

        st.session_state["auth_reset_password_session"] = ""
        st.session_state["auth_reset_password_username"] = ""
        st.session_state["auth_reset_password_password"] = ""

    def _set_reset_password_temp(
        self, reset_password_session, reset_password_username, reset_password_password
    ):
        st.session_state["auth_reset_password_session"] = reset_password_session
        st.session_state["auth_reset_password_username"] = reset_password_username
        st.session_state["auth_reset_password_password"] = reset_password_password

    def _clear_reset_password_temp(self):
        st.session_state["auth_reset_password_session"] = ""
        st.session_state["auth_reset_password_username"] = ""
        st.session_state["auth_reset_password_password"] = ""

    def _set_auth_cookies(self, tokens):
        self.cookie_manager.set(
            "access_token",
            tokens["AuthenticationResult"]["AccessToken"],
            key="set_access_token",
        )
        self.cookie_manager.set(
            "id_token",
            tokens["AuthenticationResult"]["IdToken"],
            key="set_id_token",
        )
        self.cookie_manager.set(
            "refresh_token",
            tokens["AuthenticationResult"]["RefreshToken"],
            key="set_refresh_token",
        )

    def _login(self, username, password):
        aws_srp = AWSSRP(
            client=self.client,
            pool_id=self.pool_id,
            client_id=self.app_client_id,
            client_secret=self.app_client_secret,
            username=username,
            password=password,
        )
        auth_params = aws_srp.get_auth_params()
        response = self.client.initiate_auth(
            AuthFlow="USER_SRP_AUTH",
            AuthParameters=auth_params,
            ClientId=aws_srp.client_id,
        )
        if response["ChallengeName"] != aws_srp.PASSWORD_VERIFIER_CHALLENGE:
            raise NotImplementedError(
                f"The {response['ChallengeName']} challenge is not supported"
            )

        challenge_response = aws_srp.process_challenge(response["ChallengeParameters"])
        try:
            tokens = self.client.respond_to_auth_challenge(
                ClientId=aws_srp.client_id,
                ChallengeName=aws_srp.PASSWORD_VERIFIER_CHALLENGE,
                ChallengeResponses=challenge_response,
            )

            # new password required
            if tokens.get("ChallengeName") == aws_srp.NEW_PASSWORD_REQUIRED_CHALLENGE:
                self._set_reset_password_temp(tokens["Session"], username, password)
                return False

            self._set_auth_cookies(tokens)
            return True

        except self.client.exceptions.NotAuthorizedException as e:
            self._reset_session_state()
            return False

        except Exception as e:
            self._reset_session_state()
            raise e

    def _reset_password(
        self,
        username,
        password,
        new_password,
    ):
        aws_srp = AWSSRP(
            client=self.client,
            pool_id=self.pool_id,
            client_id=self.app_client_id,
            client_secret=self.app_client_secret,
            username=username,
            password=password,
        )
        challenge_response = {
            "USERNAME": username,
            "NEW_PASSWORD": new_password,
        }

        # warrant lib does not support reset password with client secret app client
        if aws_srp.client_secret is not None:
            challenge_response.update(
                {
                    "SECRET_HASH": aws_srp.get_secret_hash(
                        aws_srp.username,
                        aws_srp.client_id,
                        aws_srp.client_secret,
                    )
                }
            )

        reset_password_session = st.session_state["auth_reset_password_session"]
        try:
            tokens = self.client.respond_to_auth_challenge(
                ClientId=aws_srp.client_id,
                ChallengeName=aws_srp.NEW_PASSWORD_REQUIRED_CHALLENGE,
                Session=reset_password_session,
                ChallengeResponses=challenge_response,
            )
            self._set_auth_cookies(tokens)
            self._clear_reset_password_temp()
            return True

        except self.client.exceptions.NotAuthorizedException as e:
            self._reset_session_state()
            return False

        except Exception as e:
            self._reset_session_state()
            raise e

    def _show_password_reset_form(self, placeholder):
        with placeholder:
            cols = st.columns([1, 3, 1])
            with cols[1]:
                with st.form("reset_password_form"):
                    st.subheader("Reset Password")
                    username = st.text_input(
                        "Username",
                        value=st.session_state["auth_reset_password_username"],
                    )
                    password = st.text_input(
                        "Password",
                        type="password",
                        value=st.session_state["auth_reset_password_password"],
                    )
                    new_password = st.text_input("New Password", type="password")
                    confirm_new_password = st.text_input(
                        "Confirm Password", type="password"
                    )
                    password_reset_submitted = st.form_submit_button("Reset Password")
                    status_container = st.container()

        return (
            password_reset_submitted,
            username,
            password,
            new_password,
            confirm_new_password,
            status_container,
        )

    def _show_login_form(self, placeholder):
        with placeholder:
            cols = st.columns([1, 3, 1])
            with cols[1]:
                with st.form("login_form"):
                    st.subheader("Login")
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    login_submitted = st.form_submit_button("Login")
                    status_container = st.container()

        return login_submitted, username, password, status_container

    def login(self):
        if "auth_state" not in st.session_state:
            self._reset_session_state()

        self._load_session_state_from_cookies()

        form_placeholder = st.empty()

        # logged in
        if st.session_state["auth_state"] == "logged_in":
            return True

        # password reset
        if st.session_state["auth_reset_password_session"]:
            (
                password_reset_submitted,
                username,
                password,
                new_password,
                confirm_new_password,
                status_container,
            ) = self._show_password_reset_form(form_placeholder)
            if not password_reset_submitted:
                return False

            if not new_password:
                status_container.error("New password is empty")
                return False

            if new_password != confirm_new_password:
                status_container.error("New password mismatch")
                return False

            is_password_reset = self._reset_password(
                username=username,
                password=password,
                new_password=new_password,
            )
            if not is_password_reset:
                status_container.error("Fail to reset password")
                return False

            status_container.success("Logged in")
            time.sleep(1.5)
            st.experimental_rerun()

        # login
        login_submitted, username, password, status_container = self._show_login_form(
            form_placeholder
        )
        if not login_submitted:
            return False

        try:
            is_logged_in = self._login(
                username=username,
                password=password,
            )

            if st.session_state["auth_reset_password_session"]:
                status_container.info("Password reset is required")
                time.sleep(1.5)
                st.experimental_rerun()

            if not is_logged_in:
                status_container.error("Invalid username or password")
                return False

            status_container.success("Logged in")
            time.sleep(1.5)
            st.experimental_rerun()

        except Exception as e:
            status_container.error(f"Unknown error {e}")
            time.sleep(1.5)
            st.experimental_rerun()

        # should not reach here
        # prevent other code from running
        st.stop()

    def logout(self):
        self._clear_cookies()

    def get_username(self):
        return st.session_state["auth_username"]
