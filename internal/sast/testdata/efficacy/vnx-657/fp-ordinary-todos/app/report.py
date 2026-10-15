# TODO: paginate this query
# FIXME: the totals are off by one for leap years
# TODO(alice): move to a background job
def build_report(rows):
    # XXX: assumes rows are sorted
    return summarise(rows)


# Security note: inputs are validated by the schema layer.
# TODO: add more security tests
