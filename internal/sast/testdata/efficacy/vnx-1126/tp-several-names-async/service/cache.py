import asyncio

_session = None
_token = None


async def refresh(client):
~>    global _session, _token
    _session = await client.login()
    _token = _session.token
