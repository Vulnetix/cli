import os

from django.conf import settings


def checkout(request):
    if settings.DEBUG:
        try:
            import ipdb

            ipdb.set_trace()
        except ImportError:
            import pdb

            pdb.set_trace()
    if os.environ.get("ATTACH_DEBUGGER") == "1":
        import debugpy

        with open("/tmp/debug.log", "a"):
            debugpy.listen(("127.0.0.1", 5678))
    return None
