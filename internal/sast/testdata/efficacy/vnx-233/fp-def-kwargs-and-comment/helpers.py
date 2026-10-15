def build(*args, **kwargs):
    # never write Model(**request.json): every field becomes settable
    note = "Model(**request.json) is mass assignment"
    return Thing(*args, **kwargs), note
