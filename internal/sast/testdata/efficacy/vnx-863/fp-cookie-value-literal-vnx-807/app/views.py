from django.shortcuts import render


def report(request):
    hint = request.COOKIES["session_hint"]
    # A cookie value compared with a privileged literal: VNX-807 reports it.
    if hint.split(":")[0] == "admin":
        return render(request, "report/full.html")
    return render(request, "report/summary.html")
