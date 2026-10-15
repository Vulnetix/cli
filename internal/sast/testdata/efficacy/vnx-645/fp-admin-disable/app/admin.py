def deactivate(request, user_id):
    if not request.user.is_staff:
        abort(403)
    user = User.query.get(user_id)
    user.is_active = False
    db.session.commit()


def retry_upload(job):
    job.attempts += 1
    if job.attempts > 3:
        job.disabled = True
