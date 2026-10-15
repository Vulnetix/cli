import asyncio


async def tap(payload: bytes, conn):
    stream = "".join(f"{b:08b}" for b in payload)
    for bit in stream:
~>        await asyncio.sleep(0.3 if bit == "1" else 0.05)
        await conn.send(b"\x00")
