import posixpath
from urllib.parse import unquote

from django.http import HttpResponseForbidden


def serve(request):
    path = posixpath.normpath(unquote(request.path))
    if path.startswith("/admin") and not request.user.is_staff:
        return HttpResponseForbidden()
    target = posixpath.normpath(path)
    return render_static(target)
