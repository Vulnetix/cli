from starlette.responses import Response


async def echo(request):
    tag = request.query_params.get("tag", "")
~>    return Response("ok", headers={"X-Tag": tag})
