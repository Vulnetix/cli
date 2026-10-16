def test_deep(accounts, ledger):
    for acct in accounts:
        if acct.active:
            for entry in ledger.entries(acct):
                if entry.pending:
                    with ledger.lock(entry):
                        if entry.amount > acct.limit:
                            entry.reject()
