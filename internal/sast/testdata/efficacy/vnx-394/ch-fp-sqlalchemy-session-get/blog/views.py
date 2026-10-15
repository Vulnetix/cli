import requests
from flask import abort

from .models import Post, db


def show(post_id):
    post = db.session.get(Post, post_id)
    if post is None:
        abort(404)
    return post.content


def preview(post_id):
    draft = session.get(Post, post_id)
    return draft.text


def ping(url):
    r = requests.get(url, timeout=3)
    r.raise_for_status()
    return r.json()
