import uvicorn
from fastapi import FastAPI

api = FastAPI(debug=False, title="debug tools")


class Task:
    debug = True

    def run(self, debug=True):
        return debug


Task().run(debug=True)
uvicorn.run(api, host="127.0.0.1", port=8000)
