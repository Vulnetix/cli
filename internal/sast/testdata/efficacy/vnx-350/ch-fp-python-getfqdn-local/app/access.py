import socket

ALLOWED_BUILD_HOSTS = {"@@sample:b[u]il[d]01[.]co[r]p[.][e]xa[m]pl[e][.]c[o]m@@"}


def running_on_build_host():
    return socket.getfqdn() in ALLOWED_BUILD_HOSTS
