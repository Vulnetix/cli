def push(client, items):
    resp = client.post(
        "/batch",
        json=items,
    )
    if resp.ok:
~>	return resp.json()
    return None
