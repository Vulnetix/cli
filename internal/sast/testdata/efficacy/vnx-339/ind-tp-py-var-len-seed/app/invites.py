import random


def generate_invite_token(team):
    seed = len(team.members)
~>    rng = random.Random(seed)
    invite_token = "%032x" % rng.getrandbits(128)
    team.invites.create(token=invite_token)
    return invite_token
