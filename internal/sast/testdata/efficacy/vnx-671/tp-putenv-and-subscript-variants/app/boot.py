import os
from os import environ

~>os.putenv("GIT_SSL_NO_VERIFY", "1")
~>environ["OAUTHLIB_INSECURE_TRANSPORT"]="1"
~>os.environ.update({"PYTHONHTTPSVERIFY": "0"})
