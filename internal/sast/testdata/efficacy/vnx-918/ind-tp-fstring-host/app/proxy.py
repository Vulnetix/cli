import httpx

def ping(request):
    host = request.GET["host"]
~>    httpx.post(f"http://{host}/hook", json={"ok": True})
    return None
