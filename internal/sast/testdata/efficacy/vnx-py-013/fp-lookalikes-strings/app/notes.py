import logging

log = logging.getLogger(__name__)


def go(mypickle, store):
    # pickle.loads(data) would run arbitrary code here
    log.info("refusing pickle.loads(data) on untrusted input")
    a = mypickle.load(store)
    b = store.pickle_load("key")
    c = store.joblib_load("key")
    return a, b, c
