import traceback


def test_trace_shape(client):
    resp = client.get("/boom")
    return jsonify(trace=traceback.format_exc())
