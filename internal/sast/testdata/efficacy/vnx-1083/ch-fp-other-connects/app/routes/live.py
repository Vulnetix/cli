import socket

import paramiko
import redis
import websockets
from flask import Blueprint

bp = Blueprint("live", __name__)


@bp.route("/ping")
async def ping():
    ws = await websockets.connect("wss://feed.example.com")
    client = paramiko.SSHClient()
    client.connect("bastion", username="deploy")
    s = socket.create_connection(("example.com", 443))
    r = redis.Redis(host="cache")
    users = User.query.filter_by(active=True).all()
    return {"ok": True}
