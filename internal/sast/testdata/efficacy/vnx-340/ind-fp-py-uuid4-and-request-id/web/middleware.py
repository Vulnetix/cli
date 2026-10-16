import uuid


def assign_ids(request):
    request.request_id = str(uuid.uuid1())
    request.session_token = uuid.uuid4().hex
    log.info("request %s", request.request_id)
