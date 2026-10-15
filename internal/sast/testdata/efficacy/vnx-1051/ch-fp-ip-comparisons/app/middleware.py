import ipaddress

TRUSTED = ipaddress.ip_network("10.0.0.0/8")


def is_internal(request):
    remote_addr = request.remote_addr
    if remote_addr == "10.0.0.1":
        return True
    return ipaddress.ip_address(remote_addr) in TRUSTED


VERSION = "1.2.3.4"
OID_SHA256 = "@@sample:2[.]16[.]84[0][.]1[.]10[1][.]3[.]4[.][2][.]1@@"
listen_host = "0.0.0.0"
