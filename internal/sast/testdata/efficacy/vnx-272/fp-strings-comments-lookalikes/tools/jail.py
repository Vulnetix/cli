import logging

log = logging.getLogger(__name__)


class Jail:
    def chroot(self, path):
        # os.chroot(path) is done by the supervisor, which then drops to nobody.
        log.info("would os.chroot(%s)", path)
        return self.supervisor.chroot(path)
