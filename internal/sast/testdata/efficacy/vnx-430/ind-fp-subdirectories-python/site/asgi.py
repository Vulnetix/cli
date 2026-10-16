from pathlib import Path

from starlette.applications import Starlette
from starlette.staticfiles import StaticFiles

app = Starlette()
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
