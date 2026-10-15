from fastapi.middleware.cors import CORSMiddleware
from flask_cors import CORS

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
)
CORS(flask_app, origins=["https://app.example.com"], supports_credentials=True)
CORS(flask_app, resources={r"/api/*": {"origins": "https://app.example.com"}})
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]
CORS_ORIGIN_ALLOW_ALL = False
