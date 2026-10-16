package com.acme.billing;

public class InvoiceCounter {
    private static final String COUNTER_LOCK = "INVOICE_COUNTER";
    private long next = 1000;

    public long nextNumber() {
~>        synchronized (COUNTER_LOCK) {
            return next++;
        }
    }
}
