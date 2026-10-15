# pickle.loads on untrusted bytes runs arbitrary code; we use JSON instead.
NOTE = "Do not call pickle.loads(request.data)"
unpickler_count = 0
picklable = True
