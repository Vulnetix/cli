def export_report(user, report):
~>    assert (
        user.has_perm("reports.export")
        or user.is_superuser
    ), "forbidden"
    return render_csv(report)
