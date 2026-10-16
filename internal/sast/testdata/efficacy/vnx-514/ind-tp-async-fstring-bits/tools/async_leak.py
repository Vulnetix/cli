import asyncio


async def drip(data: bytes) -> None:
    for b in data:
        bits = f"{b:08b}"
        for bit in bits:
~>            await asyncio.sleep(0.3 if bit == "1" else 0.05)
