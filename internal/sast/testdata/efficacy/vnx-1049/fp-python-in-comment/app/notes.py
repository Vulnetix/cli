# The old report ran:
# "SELECT * FROM a JOIN b ON 1=1 JOIN c ON 1=1 JOIN d ON 1=1 JOIN e ON 1=1 JOIN f ON 1=1"
# and timed out; it was replaced by the materialised view below.
def report(cur):
    cur.execute("SELECT * FROM report_mv WHERE day = %s", (today(),))
