from django.http import JsonResponse

JOBS = []


def peek(request):
~>    job = JOBS[int(request.GET["pos"])]
    return JsonResponse(job)


def cancel(request):
    position = int(request.POST.get("position"))
~>    removed = JOBS.pop(position)
    return JsonResponse(removed)
