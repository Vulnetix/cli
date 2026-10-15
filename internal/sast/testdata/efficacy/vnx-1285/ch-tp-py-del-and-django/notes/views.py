from django.http import JsonResponse

NOTES = []


def remove(request):
    pos = int(request.POST["pos"])
~>    del NOTES[pos]
    return JsonResponse({"notes": NOTES})


def show(request):
~>    note = NOTES[int(request.GET.get("n", "0"))]
    return JsonResponse({"note": note})
