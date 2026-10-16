def sync(accounts, ledger):
    for acct in accounts:
        if acct.active:
            for entry in ledger.entries(acct):
                if entry.pending:
                    entry.reject()
