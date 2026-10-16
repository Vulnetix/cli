import os
import shutil
import logging

log = logging.getLogger(__name__)


def purge_upload(upload_dir, upload_id):
    path = os.path.join(upload_dir, upload_id)
    try:
        shutil.rmtree(path)
~>    except Exception:
        pass
    log.info("purged %s", upload_id)
