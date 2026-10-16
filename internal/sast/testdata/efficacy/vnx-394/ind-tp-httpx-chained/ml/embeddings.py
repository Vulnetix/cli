import httpx

EMBED_URL = "http://embedder.internal:8080/v1/embed"


def embed(text):
~>    return httpx.post(EMBED_URL, json={"input": text}, timeout=30.0).json()["embedding"]
