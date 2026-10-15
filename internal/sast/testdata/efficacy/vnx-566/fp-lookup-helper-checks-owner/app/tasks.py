from flask import Blueprint, abort, g, redirect, url_for

from .db import get_db

bp = Blueprint("tasks", __name__)


def load_task(task_id):
    task = get_db().execute("SELECT * FROM task WHERE id = ?", (task_id,)).fetchone()
    if task is None or task["assignee"] != g.user["id"]:
        abort(404)
    return task


@bp.route("/<int:task_id>/archive", methods=("POST",))
def archive(task_id):
    load_task(task_id)
    db = get_db()
    db.execute("UPDATE task SET archived = 1 WHERE id = ?", (task_id,))
    db.commit()
    return redirect(url_for("tasks.index"))
