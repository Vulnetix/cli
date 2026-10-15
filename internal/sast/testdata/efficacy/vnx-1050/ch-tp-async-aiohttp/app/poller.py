import aiohttp


async def push_events(stream, endpoint):
    async for event in stream:
~>        async with aiohttp.ClientSession() as session:
            await session.post(endpoint, json=event.to_dict())
