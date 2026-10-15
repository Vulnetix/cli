class Session:
    def set_trace(self, frame=None):
        self.frame = frame

    def breakpoint(self, line):
        self.lines.add(line)


def toggle(session, line):
    session.set_trace()
    session.breakpoint(line)
    gdb.breakpoint(line)
    help_text = "call pdb.set_trace() or breakpoint() to stop here"
    return help_text
