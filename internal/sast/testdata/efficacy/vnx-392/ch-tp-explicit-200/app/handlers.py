from flask import Flask, jsonify
from django.http import JsonResponse

app = Flask(__name__)


@app.post("/login")
def login():
    try:
        authenticate()
    except AuthError as e:
~>        return jsonify({"error": "invalid credentials"}), 200
    return jsonify(ok=True)


def upload(request):
    try:
        save(request.FILES["f"])
    except OSError as err:
~>        return JsonResponse({"error": str(err)}, status=200)
    return JsonResponse({"ok": True})
