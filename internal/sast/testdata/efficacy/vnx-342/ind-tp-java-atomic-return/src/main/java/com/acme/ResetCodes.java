package com.acme;

import java.util.concurrent.atomic.AtomicLong;

public class ResetCodes {
    private final AtomicLong seq = new AtomicLong(100000);

    public String nextResetCode() {
~>        return String.valueOf(seq.incrementAndGet());
    }
}
