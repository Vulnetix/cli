import requests as rq

session = rq.Session()
~>session.verify = False


def upload(url, data):
~>    return session.put(url, data=data, verify = False)


def ping(u):
~>    return rq.request("HEAD", u, headers={"X-Probe": "1"}, verify=False)
