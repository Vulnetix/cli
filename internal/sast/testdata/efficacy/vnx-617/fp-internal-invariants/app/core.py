def build(nodes, request):
    assert isinstance(request, Request)
    assert request is not None
    assert len(nodes) > 0, "graph must not be empty"
    assert self.user_count >= 0
    user_input_buffer = []
    assert not user_input_buffer
    return nodes


def dispatch(self, request):
    meth = getattr(self, request.method.lower(), None)
    assert meth is not None, f"Unimplemented method {request.method!r}"
    return meth()
