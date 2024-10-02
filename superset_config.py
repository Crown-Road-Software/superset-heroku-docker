import os
from flask_appbuilder.security.manager import AUTH_OAUTH
#---------------------------------------------------------
# Superset specific config
#---------------------------------------------------------
# ROW_LIMIT = 5000
SUPERSET_WORKERS = 8 # for it to work in heroku basic/hobby dynos increase as you like
SUPERSET_WEBSERVER_PORT = os.environ['PORT']
#---------------------------------------------------------
MAPBOX_API_KEY = os.getenv('MAPBOX_API_KEY')

#---------------------------------------------------------
# Flask App Builder configuration
#---------------------------------------------------------
# Your App secret key
SECRET_KEY = os.environ['SECRET_KEY']

# The SQLAlchemy connection string to your database backend
# This connection defines the path to the database that stores your
# Superset metadata (slices, connections, tables, dashboards, ...).
# Note that the connection information to connect to the datasources
# you want to explore are managed directly in the web UI
SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']

AUTH_TYPE = AUTH_OAUTH
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"
OAUTH_PROVIDERS = [
    {
        "name": "google",
        "icon": "fa-google",
        "token_key": "access_token",
        "remote_app": {
            "client_id": os.environ['GOOGLE_CLIENT_ID'],
            "client_secret": os.environ['GOOGLE_CLIENT_SECRET'],
            "api_base_url": "https://www.googleapis.com/oauth2/v2/",
            "client_kwargs": {
                "scope": "openid email profile",
                "token_endpoint_auth_method": "client_secret_basic"
            },
            "request_token_url": None,
            "access_token_url": "https://oauth2.googleapis.com/token",
            "authorize_url": "https://accounts.google.com/o/oauth2/auth",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "authorize_params": {"hd": "crownroadsoftware.com"}
        },
    }
]

OAUTH_USER_INFO = {
    "google": (
        "GET",
        "https://www.googleapis.com/oauth2/v2/userinfo",
        {
            "email": lambda x: x.get("email"),
        },
    )
}

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = CSRF_ENABLED = True

# use inserted X-Forwarded-For/X-Forwarded-Proto headers
ENABLE_PROXY_FIX = True
SQLLAB_ASYNC_TIME_LIMIT_SEC = 300
SQLLAB_TIMEOUT = 300
SUPERSET_WEBSERVER_TIMEOUT = 300
