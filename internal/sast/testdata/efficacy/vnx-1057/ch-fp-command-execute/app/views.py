from flask import Blueprint

from app.commands import RebuildIndex
from app.store import ItemStore

bp = Blueprint("admin", __name__)


@bp.post("/admin/rebuild")
def rebuild():
    command = RebuildIndex()
    command.execute("SELECT-ALL-SHARDS")
    ws = connect_socket()
    ws.connect()
    return ItemStore().count()
