from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import get_object_or_404, redirect

from .models import Member


@staff_member_required
def deactivate_member(request, member_id):
    member = get_object_or_404(Member, pk=member_id)
    if request.method == "POST":
        member.is_active = False
        member.is_locked = True
        member.save()
    return redirect("staff:members")
