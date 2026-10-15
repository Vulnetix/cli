import csv
import tempfile as tf


def export_rows(rows, upload):
~>    tmp = tf.NamedTemporaryFile(
        mode="w",
        suffix=".csv",
        delete=False,
    )
    writer = csv.writer(tmp)
    writer.writerows(rows)
    tmp.close()
    upload(tmp.name)
