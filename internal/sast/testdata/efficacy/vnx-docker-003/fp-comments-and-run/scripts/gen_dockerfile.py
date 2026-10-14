LINES = [
    "FROM alpine:3.20",
    "ENV API_TOKEN=placeholder",
]
TEMPLATE = """
ENV DB_PASSWORD=from-template
"""
