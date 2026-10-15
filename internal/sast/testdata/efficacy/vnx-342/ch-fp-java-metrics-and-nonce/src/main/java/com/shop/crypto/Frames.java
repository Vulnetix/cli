package com.shop.crypto;

import java.util.concurrent.atomic.AtomicLong;

public class Frames {
    private final AtomicLong requestCounter = new AtomicLong();
    private final AtomicLong nonceCounter = new AtomicLong();

    public long next() {
        requestCounter.incrementAndGet();
        long nonce = nonceCounter.incrementAndGet();
        return nonce;
    }
}
