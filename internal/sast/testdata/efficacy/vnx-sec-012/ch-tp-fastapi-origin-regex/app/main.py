from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
~>    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
)
