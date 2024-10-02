from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.views import AuthOAuthView
from flask_login import login_user
from flask import redirect, request, flash
import logging

class CustomAuthOAuthView(AuthOAuthView):
    @expose("/oauth-authorized/<provider>")
    def oauth_authorized(self, provider):
        logging.debug("Authorized init")
        resp = self.appbuilder.sm.oauth_remotes[provider].authorized_response()
        if resp is None:
            flash("You denied the request to sign in.", "warning")
            return redirect("/login")

        logging.debug(f"OAUTH Authorized response: {resp}")

        try:
            self.appbuilder.sm.set_oauth_session(provider, resp)
            userinfo = self.appbuilder.sm.oauth_user_info(provider, resp)
        except Exception as e:
            logging.error(f"Error retrieving user info: {str(e)}")
            flash("An error occurred while retrieving your user information.", "danger")
            return redirect("/login")

        logging.debug(f"User info: {userinfo}")

        # First, try to find user by email
        user = self.appbuilder.sm.find_user(email=userinfo.get("email"))

        if user:
            login_user(user)
            return redirect(self.appbuilder.get_url_for_index)
        else:
            # If user not found by email, you could implement additional logic here
            # For example, you could check if a user exists with a username matching the email
            user = self.appbuilder.sm.find_user(username=userinfo.get("email"))
            if user:
                login_user(user)
                return redirect(self.appbuilder.get_url_for_index)
            else:
                flash("User not found. Please contact your administrator.", "warning")
                return redirect("/login")

class CustomSecurityManager(SupersetSecurityManager):
    authview = CustomAuthOAuthView

    def oauth_user_info(self, provider, response=None):
        if provider == 'google':
            res = super(CustomSecurityManager, self).oauth_user_info(provider, response)
            # We're not modifying the username here anymore
            return res
        return {}