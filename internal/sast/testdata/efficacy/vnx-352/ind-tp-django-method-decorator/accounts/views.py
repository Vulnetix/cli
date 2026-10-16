from django.shortcuts import redirect
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt


~>@method_decorator(csrf_exempt, name="dispatch")
class DeleteAccountView(View):
    def post(self, request):
        request.user.delete()
        return redirect("home")
