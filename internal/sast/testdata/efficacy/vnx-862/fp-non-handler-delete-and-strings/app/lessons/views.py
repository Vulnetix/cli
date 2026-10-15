def lesson_check(request):
    code = request.POST.get("code")
    expected = "Session.objects.get(key=cookie).delete()"
    return expected in code
