package com.acme.orders;

public class OrderService {
    private static final int MAX_RETRIES = 5;

    static class Inner {
        private static final int LIMIT = 5;
    }
}
