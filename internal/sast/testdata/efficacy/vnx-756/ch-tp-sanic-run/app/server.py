from sanic import Sanic
from sanic.response import text

app = Sanic("orders")


@app.get("/")
async def index(request):
    return text("ok")


if __name__ == "__main__":
~>    app.run(host="0.0.0.0", port=8000, debug=True)
