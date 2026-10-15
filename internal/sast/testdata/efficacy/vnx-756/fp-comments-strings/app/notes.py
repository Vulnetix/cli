from fastapi import FastAPI

# api = FastAPI(debug=True) shows tracebacks
HELP = "never deploy FastAPI(debug=True)"
api = FastAPI(title="x")
