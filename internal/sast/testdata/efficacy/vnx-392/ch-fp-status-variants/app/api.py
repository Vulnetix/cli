from http import HTTPStatus

from flask import Flask, Response, jsonify, make_response

app = Flask(__name__)


@app.post("/import")
def do_import():
    try:
        run_import()
    except ValueError as e:
        return jsonify(error=str(e)), HTTPStatus.BAD_REQUEST
    except KeyError as e:
        return make_response(jsonify({"error": "missing key"}), 422)
    except RuntimeError:
        return Response(
            '{"error": "import failed"}',
            mimetype="application/json",
            status=503,
        )
    except Exception as e:
        return {"error": str(e)}, 500
    return jsonify(done=True)
