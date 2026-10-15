from django.http import JsonResponse


def search(request):
~>    users = User.objects.filter(**request.GET.dict())
~>    Profile.objects.create(**request.POST.dict(), owner=request.user)
    return JsonResponse({"users": list(users.values("id", "name"))})
