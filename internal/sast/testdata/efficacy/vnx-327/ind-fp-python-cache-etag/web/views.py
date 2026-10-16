import hashlib
import json

from django.core.cache import cache
from django.http import JsonResponse


def report(request, report_id):
    payload = json.dumps(build_report(report_id), sort_keys=True)
    etag = hashlib.md5(payload.encode()).hexdigest()
    cache_key = "report:" + hashlib.sha1(str(report_id).encode()).hexdigest()
    cache.set(cache_key, payload, 300)
    response = JsonResponse(json.loads(payload))
    response["ETag"] = etag
    return response
