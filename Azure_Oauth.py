import os
import dotenv

import urllib.parse
import requests
import streamlit as st
from Role import Role, no_access_role
import logging

st_logger = logging.getLogger(__name__)
st_logger.addHandler(logging.StreamHandler())
st_logger.setLevel(level=logging.INFO)

dotenv.load_dotenv(override=True)

class Azure_Oauth:
    def __init__(self, client_id, client_secret, tenant_id, subscriptionId, redirect_uri = 'http://localhost:8501/'):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.subscriptionId = subscriptionId
        self.redirect_uri = redirect_uri
        self.auth_code = None

    def _get_auth_link(self, scope):
        auth_link = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/authorize?" + f"""
          client_id={self.client_id}&
          response_type=code&
          redirect_uri={urllib.parse.quote(self.redirect_uri, safe="")}&
          scope={urllib.parse.quote(scope[0], safe="")}&
          form_post=query
        """.replace("\n", "").replace(" ", "")
        st_logger.info("Auth link: " + auth_link)
        return auth_link
    
    def show_login_button(self):
        auth_link = self._get_auth_link(scope=["offline_access https://management.azure.com/.default"])
        button = f"""<a href="{auth_link}" target="_blank">
        <div class="mt-2">
            <button type="button" id="microsoft-login-button"
                    class="w-full py-3 px-4 inline-flex justify-center items-center gap-2 rounded-md border font-medium bg-white text-gray-700 shadow-sm align-middle hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-white focus:ring-primary-600 transition-colors text-sm dark:border-gray-700 dark:focus:ring-offset-gray-800">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="16" viewBox="0 0 20 20" >
                    <rect x="1" y="7" width="5" height="5" fill="#f25022"/>
                    <rect x="1" y="14" width="5" height="5" fill="#00a4ef"/>
                    <rect x="7" y="7" width="5" height="5" fill="#7fba00"/>
                    <rect x="7" y="14" width="5" height="5" fill="#ffb900"/>
                </svg>
                Sign in with Microsoft
            </button>
        </div></a>"""
        with st.sidebar:
            st.components.v1.html(button, height=50)

    def _get_initial_token(self, scope):
        data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": self.auth_code,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "client_secret": self.client_secret
        }
        response = requests.post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token", data=data
        )
        st_logger.debug("Token response: " + str(response.content))
        response_json = response.json()
        st.session_state["refresh_token"] = response_json.get("refresh_token")
        st.session_state["user_access_token"] = response_json.get("access_token")
        return response_json["access_token"] if "access_token" in response_json else None

    def get_app_access_token(self, scope):
        if not st.session_state.get("logged_in", False):
            st_logger.error("User not logged in")
            return None 
        if scope == st.session_state.get("app_current_scope") and \
            st.session_state.get("app_access_token") is not None:
            return st.session_state["app_access_token"]
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "scope": scope,
            "client_secret": self.client_secret
        }
        response = requests.post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token", data=data
        )
        st_logger.debug("Token response: " + str(response.content))
        st.session_state["app_access_token"] = response.json()["access_token"]
        st.session_state["app_current_scope"] = scope
        return st.session_state["app_access_token"]
    
    def get_user_access_token(self, scope:str):
        if "refresh_token" not in st.session_state:
            st_logger.info("No refresh token found")
            return None
        if scope == st.session_state.get("user_current_scope") and \
            st.session_state.get("user_access_token") is not None:
            return st.session_state["user_access_token"]
        if "offline_access" not in scope:
            scope = "offline_access " + scope
        refresh_data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": st.session_state["refresh_token"],
            "scope": scope,
            "client_secret": self.client_secret
        }
        response_json = requests.post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token", data=refresh_data
        ).json()
        st.session_state["user_access_token"] = response_json["access_token"]
        st.session_state["refresh_token"] = response_json["refresh_token"]
        st.session_state["user_current_scope"] = scope
        return st.session_state["user_access_token"]
    
    @st.cache_resource
    def _get_roles_from_azure(_self):
        if not st.session_state.get("logged_in", False):
            st_logger.error("User not logged in")
            return None
        token = _self.get_app_access_token(scope=["https://storage.azure.com/.default"])

        storage_account_name = os.environ["storage_account_name"]
        container_name = os.environ["container_name"]
        roles_file_path = os.environ["roles_file_path"]

        response = requests.get(
            f"https://{storage_account_name}.blob.core.windows.net/{container_name}/{roles_file_path}",
            headers={
                "Authorization": "Bearer " + token,
                "x-ms-version": "2017-11-09"
            }
        )
        if response.status_code == 200:
            return response.json()["roles"]
        else:
            st_logger.warning("No roles found")
            st_logger.warning(response.content)
            return []

    def get_role(self):
        if not st.session_state.get("logged_in", False):
            st_logger.error("User not logged in")
            return None
        for role in [Role(**role) for role in self._get_roles_from_azure()]:
            if self._in_ad_group(role.ad_group):
                return role
        else:
            return no_access_role

    def _in_ad_group(self, group_name):
        if not st.session_state.get("logged_in", False):
            st_logger.error("User not logged in")
            return False
        return group_name in st.session_state["ad_groups"]

    def _get_user_information(self):
        token = self._get_initial_token(scope=["offline_access https://graph.microsoft.com/.default"])
        if token is None:
            return None
        st.session_state["logged_in"] = True
        response_json_user_data = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": "Bearer " + token}
        )
        st_logger.debug("User data: " + str(response_json_user_data.content))
        response_json_user_ad_groups = requests.get(
            "https://graph.microsoft.com/v1.0/me/memberOf",
            headers={"Authorization": "Bearer " + token}
        )
        st_logger.debug("User AD groups: " + str(response_json_user_ad_groups.content))
        assigned_groups = [group["displayName"] for group in response_json_user_ad_groups.json()["value"]]
        return response_json_user_data.json()["displayName"], assigned_groups

    def logged_in(self):
        if st.query_params.get("code") is not None:
            self.auth_code = st.query_params.get("code")
            st.query_params.clear()
            st.session_state["userName"], st.session_state["ad_groups"] = self._get_user_information()
        if st.session_state.get("logged_in", False):
            with st.sidebar:
                st.markdown(f"**Logged in as:** {st.session_state['userName']} <br>**Role:** {self.get_role().role_name}", unsafe_allow_html=True)
            return True
        return False
    