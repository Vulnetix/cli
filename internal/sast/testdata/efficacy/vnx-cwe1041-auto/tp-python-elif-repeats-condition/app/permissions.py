def role_for(request):
    user = request.user
    if user.is_superuser:
        return "admin"
    elif user.is_staff:
        return "staff"
~>    elif user.is_superuser:
        return "auditor"
    return "member"


def can_export(user, report):
~>    if user.has_perm("reports.export") and user.has_perm("reports.export"):
        return report.owner_id == user.id
    return False
