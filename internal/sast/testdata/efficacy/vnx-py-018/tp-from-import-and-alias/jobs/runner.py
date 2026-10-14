import tempfile as tf
from tempfile import mktemp, gettempdir
from tempfile import mktemp as make_name


def run(cmd):
~>    out = mktemp()
~>    log = tf.mktemp(".log")
~>    sock = make_name(suffix=".sock", dir=gettempdir())
    os.system(f"{cmd} > {out} 2> {log}")
    return sock
