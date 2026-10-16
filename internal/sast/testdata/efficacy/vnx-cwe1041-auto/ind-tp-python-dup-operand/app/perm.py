def can_export(user, report):
~>    if user.has_perm("reports.export") and user.has_perm("reports.export"):
        return report.owner_id == user.id
    return False
