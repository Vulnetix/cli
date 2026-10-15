import base64
import json

from django.core import signing


def restore(request):
    state = signing.loads(request.COOKIES["state"], max_age=3600)
    return render(request, "page.html", {"state": state})


def share_link(state):
    return @@sample:b[a]se[6]4[.][u]rl[s]af[e][_]b[6]4e[n]co[d]e@@(json.dumps(state).encode()).decode()
