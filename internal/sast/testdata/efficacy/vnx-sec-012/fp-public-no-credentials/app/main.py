from fastapi.middleware.cors import CORSMiddleware

# Public, unauthenticated read-only dataset API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
)
