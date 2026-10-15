def set_policy(graph, user_id):
    graph.patch(f"/users/{user_id}", json={"passwordPolicies": "None"})


def report(entries):
    flagged = [e for e in entries if e["userAccountControl"] & 0x10000]
    return flagged
