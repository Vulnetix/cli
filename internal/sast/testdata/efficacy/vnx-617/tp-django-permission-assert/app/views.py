from django.http import JsonResponse


def delete_user(request, user_id):
~>    assert request.user.is_authenticated
~>    assert request.user.is_superuser, "admins only"
    target = User.objects.get(pk=user_id)
~>    assert target.owner_id == request.user.id
    target.delete()
    return JsonResponse({"ok": True})


def edit(user, doc):
~>    assert user.has_perm("docs.change_document")
~>    assert doc.can_edit(user)
    doc.save()
