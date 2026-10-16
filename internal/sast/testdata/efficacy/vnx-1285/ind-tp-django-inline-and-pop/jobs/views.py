JOBS = []


def detail(request):
~>    job = JOBS[int(request.GET["pos"])]
    return job


def drop(request):
    n = int(request.POST["position"])
~>    JOBS.pop(n)
    return None
