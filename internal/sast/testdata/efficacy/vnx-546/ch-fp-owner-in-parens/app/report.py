def build_report(rows):
    # TODO(security-team): rename this module once the reporting split lands
    total = sum(r.amount for r in rows)
    # TODO: remove once the Auth0 migration is finished
    return {"total": total}
