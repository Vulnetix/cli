from django.db.models.expressions import RawSQL

from app.models import Event


def recent(days):
~>    return Event.objects.extra(where=[f"created > now() - interval '{days} days'"])


def annotate(qs, col):
~>    return qs.annotate(val=RawSQL("SELECT %s FROM app_stats" % col, ()))


def by_kind(kind):
~>    return Event.objects.raw("SELECT * FROM app_event WHERE kind = '%s'" % kind)
