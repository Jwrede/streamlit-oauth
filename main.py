import os

import streamlit as st
import dotenv

from Azure_Oauth import Azure_Oauth

dotenv.load_dotenv(override=True)

st.set_page_config(layout="wide")

client_id = os.environ["client_id"]
tenant_id = os.environ["tenant_id"]
subscriptionId = os.environ["subscriptionId"]
redirect_uri= os.environ["redirect_uri"]
client_secret = os.environ["client_secret"]
storage_account_name = os.environ["storage_account_name"]
container_name = os.environ["container_name"]

app = Azure_Oauth(client_id, client_secret, tenant_id, subscriptionId, redirect_uri)  


if app.logged_in():
    user_role = app.get_role()
    if user_role.may_see_app:
        st.markdown("#### You are logged in")
        st.markdown("#### You have access to the app")
    else:
        st.markdown("#### You are logged in")
        st.markdown("#### You do not have access to the app")
else:
    st.markdown("#### Login required")
    app.show_login_button()