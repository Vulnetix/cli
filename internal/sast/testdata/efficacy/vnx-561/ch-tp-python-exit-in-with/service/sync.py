import logging

log = logging.getLogger(__name__)


def push(client, batch):
    with client.session() as s:
        if not batch:
            return None
~>            log.info("empty batch skipped")
        for row in batch:
            if row.get("skip"):
                continue
~>                log.debug("skipping %s", row["id"])
            s.send(row)
    return len(batch)
