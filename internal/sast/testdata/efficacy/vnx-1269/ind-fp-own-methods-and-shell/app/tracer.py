import code


class Tracer:
    def set_trace(self, fn):
        self.fn = fn

    def breakpoint(self):
        return self.fn


def go(t: Tracer):
    t.set_trace(print)
    t.breakpoint()


def shell_command(ns):
    code.interact(local=ns)


# remember to remove pdb.set_trace() before release
HELP = "call breakpoint() to stop"
