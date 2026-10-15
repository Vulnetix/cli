from sanic import Sanic
from sanic.response import json

app = Sanic("inventory")


@app.get("/items/<sku>")
async def item(request, sku):
    try:
        row = await store.fetch(sku)
    except LookupError:
~>        return json({"error": "item not found"})
    return json(row)


@app.get("/health")
async def health(request):
    try:
        await store.ping()
    except Exception as exc:
        return json({"error": str(exc)}, status=503)
    return json({"ok": True})
