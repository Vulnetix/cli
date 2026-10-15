import logging
import traceback


class OneLineFormatter(logging.Formatter):
    def formatException(self, ei):
        return "".join(traceback.format_exception(*ei)).replace("\n", " | ")


def crash_report():
    """Text written to the crash file on disk, never to a client."""
    return traceback.format_exc()


def main():
    try:
        run()
    except Exception:
        with open("/var/log/app/crash.txt", "w") as fh:
            fh.write(crash_report())


def run():
    pass
