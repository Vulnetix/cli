import os
import tempfile as tf


def prepare():
~>    os.chdir(tf.mkdtemp())
    open("marker", "w").close()
