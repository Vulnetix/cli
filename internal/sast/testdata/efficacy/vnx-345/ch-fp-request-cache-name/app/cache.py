import pickle

from django.http import JsonResponse


def cached_report(request, report_id):
    path = f"/var/cache/reports/{int(report_id)}.pkl"
    with open(path, "rb") as fh:
        report = pickle.load(fh)
    return JsonResponse({"user": request.user.username, "rows": len(report)})
