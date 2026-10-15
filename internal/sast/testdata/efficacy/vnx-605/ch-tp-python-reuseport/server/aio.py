import asyncio


async def serve(handler, port):
    loop = asyncio.get_running_loop()
~>    server = await loop.create_server(handler, host="0.0.0.0", port=port, reuse_port=True)
    return server
