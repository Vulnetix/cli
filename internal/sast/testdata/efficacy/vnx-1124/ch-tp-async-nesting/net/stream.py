async def pump(session, urls):
    async with session:
        for url in urls:
            async with session.get(url) as resp:
                async for chunk in resp.content:
                    if chunk:
~>                        match chunk[0]:
                            case 0:
                                await handle(chunk)
