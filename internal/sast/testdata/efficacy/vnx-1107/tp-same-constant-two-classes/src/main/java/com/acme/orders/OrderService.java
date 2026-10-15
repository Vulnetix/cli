package com.acme.orders;

public class OrderService {
~>    private static final int MAX_RETRIES = 5;
~>    public static final long REQUEST_TIMEOUT_MS = 30_000L;

    public void place(Order o) {
        for (int i = 0; i < MAX_RETRIES; i++) {
            submit(o, REQUEST_TIMEOUT_MS);
        }
    }
}
