from django.core.exceptions import PermissionDenied


def assert_permission(user, perm):
    if not user.has_perm(perm):
        raise PermissionDenied(perm)


def delete_project(user, project):
    assert_permission(user, "projects.delete")
    # assert user.is_admin  -- replaced by assert_permission above
    if not project.is_owner(user):
        raise PermissionDenied("not the owner")
    assert project.pk is not None
    project.delete()
