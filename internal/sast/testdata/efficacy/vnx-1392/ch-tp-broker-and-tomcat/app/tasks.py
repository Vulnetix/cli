import os

from celery import Celery

app = Celery("tasks", broker=os.environ["CELERY_BROKER_URL"])
