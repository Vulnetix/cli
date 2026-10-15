import asyncio
import os
import socket
import socketserver
import tempfile

SOCK_PATH = "/tmp/agent.sock"
PIPE = os.path.join(tempfile.gettempdir(), "agent.fifo")


def serve_raw():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
~>    s.bind(SOCK_PATH)
    s.listen(1)


def make_pipe():
~>    os.mkfifo(PIPE)


async def serve_async(handler):
~>    server = await asyncio.start_unix_server(handler, path="/tmp/agent-async.sock")
    return server


def serve_ss(handler):
~>    return socketserver.UnixStreamServer('/var/tmp/agent-ss.sock', handler)
