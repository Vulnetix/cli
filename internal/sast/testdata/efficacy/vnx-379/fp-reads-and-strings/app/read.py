import logging

log = logging.getLogger(__name__)


def load():
    # with open("/tmp/report.json", "w") as fh:
    with open("/tmp/report.json") as fh:
        data = fh.read()
    log.info("writing to /tmp/report.json is unsafe")
    help_text = 'open("/tmp/x", "w")'
    with open("/etc/app/settings.json", "w") as cfg:
        cfg.write(data)
    return data, help_text
