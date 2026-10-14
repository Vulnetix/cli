import logging

log = logging.getLogger(__name__)


def run(executor, job, cur, uid):
    executor.execute(f"job-{job.id}")
    print(f"SELECT * FROM users WHERE id = {uid}")
    # cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    log.info("never call cur.execute(f\"SELECT {x}\") with user data")
    resp = client.raw(f"/v1/jobs/{job.id}")
    return resp
