from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render


@user_passes_test(lambda u: u.is_superuser)
def admin_home(request):
    section = "reports" if request.path.endswith("/reports") else "home"
    return render(request, "dashboard/admin.html", {"section": section})
