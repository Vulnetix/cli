import psycopg2


class Ledger:
    def __init__(self, dsn):
        self.conn = psycopg2.connect(dsn)

    def balances(self, account_ids):
~>        cur = self.conn.cursor()
        cur.execute(
            "SELECT account_id, balance FROM ledger_balance WHERE account_id = ANY(%s)",
            (list(account_ids),),
        )
        rows = cur.fetchall()
        return {account_id: balance for account_id, balance in rows}
