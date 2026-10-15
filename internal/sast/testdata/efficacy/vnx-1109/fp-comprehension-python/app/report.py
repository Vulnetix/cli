def names(users):
    out = []
    for user in users:
        out.append([
            user.name
            for user in user.friends
        ])
    return out
