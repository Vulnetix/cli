from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()

~>app.mount("/", StaticFiles(directory=Path(__file__).parent, html=True), name="site")
