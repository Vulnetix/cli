import logging
import traceback

log = logging.getLogger(__name__)


def run_job(job):
    try:
        job.run()
    except Exception:
        traceback.print_exc()
        log.error("job %s failed\n%s", job.id, traceback.format_exc())
        log.exception("job failed")
        return {"status": "failed"}


def main():
    try:
        serve()
    except KeyboardInterrupt:
        traceback.print_exc(file=sys.stderr)
