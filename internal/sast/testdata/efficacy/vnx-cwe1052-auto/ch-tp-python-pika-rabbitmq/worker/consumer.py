import pika

params = pika.ConnectionParameters(
~>    host="@@sample:r[a]bb[i]t[-][0]1[.][p]ro[d][.]a[c]me[-]co[r]p[.][n]et@@",
    port=5672,
    heartbeat=30,
)
~>fallback = pika.ConnectionParameters("10.8.0.30")
connection = pika.BlockingConnection(params)
channel = connection.channel()
