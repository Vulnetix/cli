from django.shortcuts import redirect
from django.views.decorators.http import require_POST


@require_POST
def switch_workspace(request):
    workspace = request.POST.get("workspace")
    request.session["workspace"] = workspace
~>    request.session["role"] = request.POST.get("role", "viewer")
    return redirect("/dashboard/")
