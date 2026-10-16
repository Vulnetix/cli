import uvicorn
from flask import Flask


class Task:
    debug = True

    def run(self, debug=True):
        return debug


def main(task):
    task.run(debug=True)
    uvicorn.run("app:app", debug=True)
    # app.run(debug=True) would expose the console
    return "app.run(debug=True)"
