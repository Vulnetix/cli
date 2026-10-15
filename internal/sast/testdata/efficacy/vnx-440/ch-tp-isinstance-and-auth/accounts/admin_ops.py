from accounts.models import User


def purge_user(actor, target_id):
~>    assert isinstance(actor, User) and actor.is_superuser
    User.objects.filter(pk=target_id).delete()


def edit_document(current_user, doc):
~>    assert current_user.can_edit(doc), "forbidden"
    doc.save()
