import asyncpg

async def connect():
~>    return await asyncpg.connect(dsn='postgres://ingest:@@sample:[A-Za-z0-9]{20}@@@10.1.2.3/events')
