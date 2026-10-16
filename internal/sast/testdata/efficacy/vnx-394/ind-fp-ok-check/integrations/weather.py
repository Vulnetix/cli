import httpx


async def current_temp(client: httpx.AsyncClient, city: str):
    resp = await client.get("https://weather.internal/v1/current", params={"q": city})
    if not resp.is_success:
        return None
    return resp.json()["temp_c"]


def forecast(session, city):
    r = session.get("https://weather.internal/v1/forecast", params={"q": city})
    if r.ok:
        return r.json()
    return []
