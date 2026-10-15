package com.example;

public class Orders {
    private long lastOrderId = 0;
    private final java.util.concurrent.atomic.AtomicLong requestCounter = new java.util.concurrent.atomic.AtomicLong();

    public long place(String[] tokens) {
        for (int i = 0; i < tokens.length; i++) {
            validate(tokens[i]);
        }
        long orderId = lastOrderId + 1;
        long requestId = requestCounter.incrementAndGet();
        lastOrderId = orderId;
        return orderId;
    }
}
