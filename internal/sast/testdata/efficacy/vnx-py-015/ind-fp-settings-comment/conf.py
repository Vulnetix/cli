import re
from django.conf import settings


def allowed(host):
    # re.compile(request.args.get("q")) is what we avoid here
    return re.match(settings.HOST_PATTERN, host)
