"""Nightly purge of expired sessions, run from cron."""
from app.models import db, Session


def purge_expired(cutoff):
    for s in Session.query.filter(Session.expires < cutoff):
        db.session.delete(s)
    db.session.commit()


if __name__ == "__main__":
    import datetime
    purge_expired(datetime.datetime.utcnow())
