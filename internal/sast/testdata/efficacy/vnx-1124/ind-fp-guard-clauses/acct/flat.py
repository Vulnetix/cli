def sync(accounts, ledger):
    """for if while with try: nested words in prose
                if x:
                    if y:
                        if z:
                            if w:
                                if v:
    """
    for acct in accounts:
        if not acct.active:
            continue
        for entry in ledger.entries(acct):
            if not entry.pending:
                continue
            entry.reject()  # if if if
