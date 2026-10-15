from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

app = FastAPI()

~>templates = Jinja2Templates(directory="templates", autoescape=False)

mail_env = Environment(
    loader=FileSystemLoader("mail"),
    trim_blocks=True,
~>    autoescape = False,
)


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
