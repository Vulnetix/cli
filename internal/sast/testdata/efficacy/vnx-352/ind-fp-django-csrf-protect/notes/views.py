from django.shortcuts import render, redirect
# csrf_exempt is imported for the legacy webhook module; do not use @csrf_exempt here.
from django.views.decorators.csrf import csrf_exempt, csrf_protect, ensure_csrf_cookie

from .forms import NoteForm


@ensure_csrf_cookie
def index(request):
    return render(request, "notes/index.html", {"form": NoteForm()})


@csrf_protect
def create(request):
    form = NoteForm(request.POST)
    if form.is_valid():
        form.save()
    return redirect("notes:index")
