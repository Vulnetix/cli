import logging

import uvicorn
from fastapi import FastAPI

app = FastAPI(debug=False)


class Job:
    def __init__(self):
        self.debug = True

    def run(self):
        self.runner.run(debug=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    uvicorn.run(app, debug=True)
