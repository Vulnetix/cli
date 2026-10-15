"""Timing helpers.

Older code used time.clock() and inspect.getargspec(), which are gone.
"""
import impala


class Clock:
    def clock(self):
        return 0

    def tick(self):
        # replaced base64.encodestring with encodebytes
        message = "use imp.load_source no more"
        return self.clock(), message
