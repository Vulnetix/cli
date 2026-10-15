from django.http import HttpResponseBadRequest


def validate_host_header(host):
    return host.endswith(".acme.com") or host == "acme.com"


def check_host(request_host, allowed):
    if request_host.startswith("localhost"):
        return True
    return request_host in allowed
