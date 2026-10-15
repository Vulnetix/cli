from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from flask_cors import CORS

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
~>    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)

~>CORS(flask_app, supports_credentials=True)
