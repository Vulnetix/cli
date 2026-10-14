import logging
import re

from flask import request

log = logging.getLogger(__name__)

# re.compile(request.args["p"]) would let users submit catastrophic patterns
HELP = "never call re.compile(request.args['p'])"


def page():
    log.info("blocked re.search(request.args['p'], text)")
    return re.sub(r"[<>]", "", request.args.get("name", ""))
