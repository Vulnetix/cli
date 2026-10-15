from django.shortcuts import redirect


def add_note(request):
~>    request.session["cart_note"] = request.POST.get("note", "")
    return redirect("cart")
