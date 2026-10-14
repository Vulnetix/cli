import hashlib


def cache_path(root, url):
    return root + "/http-" + hashlib.sha1(url.encode()).hexdigest()


def lock_name(job):
    return hashlib.sha1(job.encode()).hexdigest() + ".lock"
