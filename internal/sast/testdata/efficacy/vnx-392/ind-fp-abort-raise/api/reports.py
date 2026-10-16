from flask import Flask, abort, jsonify
from fastapi import HTTPException

from .store import load_report, ReportMissing

app = Flask(__name__)


@app.get("/reports/<rid>")
def get_report(rid):
    try:
        report = load_report(rid)
    except ReportMissing:
        abort(404, description="report not found")
    return jsonify(report)


async def fetch_report(rid: str):
    try:
        return load_report(rid)
    except ReportMissing as exc:
        raise HTTPException(status_code=404, detail="report not found") from exc
