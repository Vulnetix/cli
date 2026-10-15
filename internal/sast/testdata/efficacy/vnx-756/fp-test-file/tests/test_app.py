from fastapi import FastAPI
from fastapi.testclient import TestClient

app = FastAPI(debug=True)
client = TestClient(app)
