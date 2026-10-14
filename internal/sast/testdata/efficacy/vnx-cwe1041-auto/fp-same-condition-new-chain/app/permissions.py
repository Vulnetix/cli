def role_for(request):
    user = request.user
    if user.is_superuser:
        log("superuser request")
    elif user.is_staff:
        log("staff request")

    if user.is_superuser:
        return "admin"
    elif user.is_anonymous:
        return "guest"
    else:
        if user.is_staff:
            return "staff"
        elif user.is_active:
            return "member"
    return "member"


def can_export(user, report):
    if user.has_perm("reports.export") and user.has_perm("reports.view"):
        return report.owner_id == user.id
    return False
