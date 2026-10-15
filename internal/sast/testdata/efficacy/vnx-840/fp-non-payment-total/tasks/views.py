from flask import request


@bp.post("/jobs")
def start_job():
    job = runner.submit(total=request.form.get("total", type=int))
    return {"id": job.id}
