import click

from .models import Session, db

HELP = """
@app.route("/admin/delete", methods=["POST"])
def delete():
    User.query.delete()
"""


class SessionStore:
    def purge(self):
        Session.query.delete()
        db.session.commit()


@click.command()
def purge_sessions():
    # @app.route("/admin/purge") used to expose this; it is a CLI command now.
    SessionStore().purge()


def delete_expired(cursor):
    cursor.execute("DELETE FROM sessions WHERE expires < now()")


def lesson_check(request):
    code = request.POST.get("code")
    expected = "Session.objects.get(key=cookie).delete()"
    return expected in code
