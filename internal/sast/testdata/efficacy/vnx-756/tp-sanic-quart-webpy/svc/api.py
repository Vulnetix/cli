from sanic import Sanic
from sanic.response import text
import web

app = Sanic("svc")


@app.get("/")
async def hello(request):
    return text("hi")


urls = ("/", "index")
legacy = web.application(urls, globals())
~>web.config.debug = True
~>legacy.internalerror = web.debugerror

if __name__ == "__main__":
~>    app.run(host="0.0.0.0", port=8000,
            debug=True)
