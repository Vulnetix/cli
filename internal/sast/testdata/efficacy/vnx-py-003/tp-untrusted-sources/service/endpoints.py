import base64
import socket

import cPickle as pickle_mod
import dill
import pickle
import requests
import six.moves.cPickle as legacy
from fastapi import Request
from flask import request
from pickle import loads as unpickle


def restore_cart():
    raw = base64.b64decode(request.form["cart"])
~>    return pickle_mod.loads(raw)


def restore_job():
~>    return dill.loads(request.get_data())


async def submit(req: Request):
    raw = await req.body()
~>    job = pickle.loads(
        raw
    )
    return job


def serve(port):
    srv = socket.socket()
    srv.bind(("127.0.0.1", port))
    conn, _ = srv.accept()
~>    return unpickle(conn.recv(65536))


def fetch_model(url):
    resp = requests.get(url, timeout=30)
~>    return pickle.loads(resp.content)


def legacy_cache(blob):
~>    return legacy.loads(blob)


def restore_state(fh):
~>    return pickle.Unpickler(fh).load()
