def sync(accounts, ledger):
    for acct in accounts:
        if acct.active:
            for entry in ledger.entries(acct):
                if entry.pending:
                    with ledger.lock(entry):
                        if entry.amount > acct.limit:
                            entry.reject()
                        else:
                            entry.post()
                        if entry.flagged:
                            entry.audit()
    return ledger
