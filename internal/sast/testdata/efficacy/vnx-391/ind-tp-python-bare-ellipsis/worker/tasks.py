import json


def load_job_state(redis_client, job_id):
    raw = redis_client.get(f"job:{job_id}")
    state = {}
    try:
        state = json.loads(raw)
~>    except:
        ...
    return state
