from google_auth_oauthlib.flow import Flow

CLIENT_CONFIG = {
    "web": {
        "client_id": "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com",
~>        "client_secret": "GOCSPX-@@sample:[A-Za-z0-9]{28}@@",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
}
flow = Flow.from_client_config(CLIENT_CONFIG, scopes=["openid"])
