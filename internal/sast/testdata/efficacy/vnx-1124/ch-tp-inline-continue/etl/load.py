def load(batches):
    for batch in batches:
        if batch:
            for table in batch.tables:
                with table.lock():
                    for row in table.rows:
~>                        if not row: continue
                        store(row)
