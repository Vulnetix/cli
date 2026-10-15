package com.acme.billing;

public class InvoiceService {
~>    static final int MAX_RETRIES = 5;
~>    private final static long REQUEST_TIMEOUT_MS = 30_000L;

    public void send(Invoice inv) {
        for (int i = 0; i < MAX_RETRIES; i++) {
            post(inv, REQUEST_TIMEOUT_MS);
        }
    }
}
