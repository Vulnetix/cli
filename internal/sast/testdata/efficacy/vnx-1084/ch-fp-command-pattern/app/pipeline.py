def run_pipeline(ctx):
    fetch.execute()
    validate.execute()
    transform.execute()
    enrich.execute()
    score.execute()
    publish.execute()
    notify.execute()
    cleanup.execute()
    audit.execute()
    return ctx
