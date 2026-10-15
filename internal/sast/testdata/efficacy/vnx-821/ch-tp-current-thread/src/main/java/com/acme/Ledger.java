package com.acme;

import java.util.ArrayList;
import java.util.List;

public class Ledger {
    private final List<Long> entries = new ArrayList<>();

    public void post(long amount) {
~>        synchronized (Thread.currentThread()) {
            entries.add(amount);
        }
    }
}
