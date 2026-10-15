from aiohttp import web

HOST = "0.0.0.0"
PORT = 8081


def main():
    app = web.Application()
~>    web.run_app(app, host=HOST, port=PORT)
