import requests

HEADERS = {
~>    "Authorization": "Basic @@sample:c[3]Zj[L]WR[l]cG[x]ve[T]pU[c]Th[2]TD[J]tW[n]A5[V]3g[=]@@",
    "Accept": "application/json",
}


def pull(url):
    return requests.get(url, headers=HEADERS, timeout=10)
