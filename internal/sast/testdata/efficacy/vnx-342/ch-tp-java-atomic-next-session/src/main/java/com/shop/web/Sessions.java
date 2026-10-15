package com.shop.web;

import java.util.concurrent.atomic.AtomicLong;

public class Sessions {
    private static final AtomicLong nextSessionId = new AtomicLong(1000);

    public String open() {
~>        String sessionId = String.valueOf(nextSessionId.incrementAndGet());
        return sessionId;
    }
}
