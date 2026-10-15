# Remove any pdb.set_trace() before committing.
HELP = "insert breakpoint() to stop here"


def set_trace(frame):
    """A tracing hook named set_trace, not the debugger."""
    return frame


class Tracer:
    def breakpoint(self):
        return None

    def go(self, tracer):
        tracer.set_trace(None)
        self.breakpoint()
        sys_breakpointhook = None
        return sys_breakpointhook
