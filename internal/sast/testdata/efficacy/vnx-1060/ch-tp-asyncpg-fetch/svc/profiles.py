import asyncpg


async def load_profiles(pool: asyncpg.Pool, user_ids):
    profiles = {}
    async with pool.acquire() as conn:
        for uid in user_ids:
~>            row = await conn.fetchrow("SELECT * FROM profiles WHERE user_id = $1", uid)
            profiles[uid] = dict(row)
    return profiles
