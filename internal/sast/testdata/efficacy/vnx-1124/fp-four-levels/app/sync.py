class Syncer:
    def sync(self, accounts, ledger):
        for acct in accounts:
            if acct.active:
                for entry in ledger.entries(acct):
                    if entry.pending:
                        entry.post()
                        result = {
                            "id": entry.id,
                            "ok": True,
                        }
        return ledger
