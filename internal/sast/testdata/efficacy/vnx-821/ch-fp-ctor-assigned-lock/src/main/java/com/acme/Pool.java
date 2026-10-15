package com.acme;

import java.util.ArrayDeque;
import java.util.Deque;

public class Pool {
    private Object guard;
    private final Deque<String> free = new ArrayDeque<>();

    public Pool() {
        guard = new Object();
    }

    public String take() {
        synchronized (guard) {
            return free.poll();
        }
    }
}
