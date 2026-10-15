from http import HTTPStatus

from flask import Blueprint, abort, jsonify
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response

bp = Blueprint("users", __name__)


@bp.route("/users/<int:uid>")
def get_user(uid):
    try:
        return jsonify(User.load(uid).to_dict())
    except LookupError:
        return jsonify({"error": "not found"}), 404
    except ValueError as e:
        return jsonify(error=str(e)), HTTPStatus.BAD_REQUEST
    except PermissionError:
        abort(403)


def legacy(request):
    try:
        do_it()
    except ValueError:
        return JsonResponse({"message": "invalid"}, status=400)
    except Exception:
        return Response({"error": "boom"}, status=@@sample:s[t]at[u]s[.][H]TT[P][_]5[0]0[_][I]NT[E]RN[A]L[_][S]ER[V]ER[_]ER[R]OR@@)
    except OSError:
        return JsonResponse(
            {"error": "storage unavailable"},
            status=503,
        )
