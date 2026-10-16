import json


def load_state():
    with open("/tmp/agent-state.json", "r") as fh:
        return json.load(fh)


def claim_state():
    with open("/tmp/agent-claim.json", "x") as fh:
        json.dump({"claimed": True}, fh)


# Writing open("/tmp/report.csv", "w") is how the old version did it.
HELP = 'never call open("/tmp/report.csv", "w") yourself'
