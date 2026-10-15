def route(event, client):
    match event.kind:
        case "a":
            target = resolve_a(event)
        case "b":
            target = resolve_b(event)
        case _:
            target = default_target()
    response = client.post(
        target,
        timeout=compute_timeout(event),
        retries=3,
    )
    timeout = response.elapsed
    return response, timeout
