import time
import boto3

from warrant import Cognito, AWSSRP
import streamlit as st
import extra_streamlit_components as stx

# https://github.com/awslabs/aws-support-tools/blob/master/Cognito/decode-verify-jwt/decode-verify-jwt.py
from .utils import verify


class CognitoAuthenticator:
    def __init__(self, pool_id, app_client_id, app_client_secret, boto_client=None):
        self.client = boto_client or boto3.client("cognito-idp")
        self.pool_id = pool_id
        self.app_client_id = app_client_id
        self.app_client_secret = app_client_secret

        self.cookie_manager = stx.CookieManager()

    def _load_session_state_from_cookies(self):
        st.session_state["auth_access_token"] = self.cookie_manager.get("access_token")
        st.session_state["auth_id_token"] = self.cookie_manager.get("id_token")
        st.session_state["auth_refresh_token"] = self.cookie_manager.get(
            "refresh_token"
        )
        claims = self._verify_jwt(st.session_state["auth_access_token"])
        # later, refresh token

        st.write(claims)
        if not claims:
            st.session_state["auth_state"] = "logged_out"
            st.session_state["auth_username"] = ""
            st.session_state["auth_expires"] = 0
            return

        st.session_state["auth_state"] = "logged_in"
        st.session_state["auth_username"] = claims["username"]
        st.session_state["auth_expires"] = claims["exp"]

    # fake verify
    def _verify_jwt(self, access_token):
        if not access_token:
            return False

        return verify(self.pool_id, self.app_client_id, "ap-southeast-1", access_token)
        # claims = jwt.get_unverified_claims(access_token)
        # return claims

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

            # if new password required
            if tokens.get("ChallengeName") == aws_srp.NEW_PASSWORD_REQUIRED_CHALLENGE:
                self._set_reset_password_temp(tokens["Session"], username, password)
                return False

            self._set_auth_cookies(tokens)
            return True
        except self.client.exceptions.NotAuthorizedException as e:
            self._reset_session_state()
        except Exception as e:
            self._reset_session_state()
            raise e

        return False

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
        # this part is missing from warrant lib
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
            pass

        except Exception as e:
            raise e
        finally:
            self._reset_session_state()

        return False

    def login(self):
        if "auth_state" not in st.session_state:
            self._reset_session_state()

        self._load_session_state_from_cookies()

        auth_form_placeholder = st.empty()

        if st.session_state["auth_state"] == "logged_in":
            return True

        if st.session_state["auth_reset_password_session"]:
            with auth_form_placeholder:
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
                        if st.form_submit_button("Reset Password"):
                            if new_password == confirm_new_password:
                                if self._reset_password(
                                    username=username,
                                    password=password,
                                    new_password=new_password,
                                ):
                                    st.success("Logged in")
                                    time.sleep(1.5)
                                    st.experimental_rerun()
                                else:
                                    st.error("Fail to reset password")
                            else:
                                st.error("New password mismatch")
            return False

        with auth_form_placeholder:
            cols = st.columns([1, 3, 1])
            with cols[1]:
                with st.form("login_form"):
                    st.subheader("Login")
                    username = st.text_input("Username")
                    password = st.text_input("Password", type="password")
                    if st.form_submit_button("Login"):
                        if self._login(
                            username=username,
                            password=password,
                        ):
                            st.success("Logged in")
                            time.sleep(1.5)
                            st.experimental_rerun()
                        else:
                            # login fail and reset password_session was set
                            if st.session_state["auth_reset_password_session"]:
                                st.info("Password reset is required")
                                time.sleep(1.5)
                                st.experimental_rerun()
                            else:
                                st.error("Invalid username or password")

        return False

    def logout(self):
        self._clear_cookies()

    def get_username(self):
        return st.session_state["auth_username"]
