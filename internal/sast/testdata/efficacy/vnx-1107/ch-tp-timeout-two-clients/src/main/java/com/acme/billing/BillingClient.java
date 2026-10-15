package com.acme.billing;

public class BillingClient {
~>    private static final int CONNECT_TIMEOUT_MS = 15000;

    public int timeout() {
        return CONNECT_TIMEOUT_MS;
    }
}
