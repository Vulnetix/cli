import csv
import io


def test_export_headers(client):
    resp = client.get("/export.csv")
    assert resp.headers["Content-Type"] == "text/csv"
    buf = io.StringIO()
    csv.writer(buf).writerow(["=1+1"])
