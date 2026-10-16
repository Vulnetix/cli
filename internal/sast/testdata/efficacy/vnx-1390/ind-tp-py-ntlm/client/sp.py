import os
from requests_ntlm import HttpNtlmAuth

def session(s):
~>  s.auth = HttpNtlmAuth("CORP\\svc_reports", os.environ["SVC_PW"])
    return s
