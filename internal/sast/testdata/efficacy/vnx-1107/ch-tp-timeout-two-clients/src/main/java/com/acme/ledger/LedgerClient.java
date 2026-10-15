package com.acme.ledger;

public class LedgerClient {
~>    static final int CONNECT_TIMEOUT_MS = 15000;

    public int timeout() {
        return CONNECT_TIMEOUT_MS;
    }
}
