import logging

log = logging.getLogger(__name__)

# The design of the retry loop follows the architecture decision record ADR-12.
# See docs/design.md for the full design document.
# TODO: add unit tests for the parser
def parse(text):
    """Parse text. Design notes live in docs/architecture.md."""
    log.info("design doc: see wiki")
    return text.split()
