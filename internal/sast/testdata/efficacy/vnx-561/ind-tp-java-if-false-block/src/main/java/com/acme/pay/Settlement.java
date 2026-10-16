package com.acme.pay;

public class Settlement {
    private final Ledger ledger;

    public Settlement(Ledger ledger) {
        this.ledger = ledger;
    }

    public void close(Batch batch) {
        ledger.post(batch);
~>        if (false) {
            ledger.reverseAll(batch);
        }
        ledger.flush();
    }
}
