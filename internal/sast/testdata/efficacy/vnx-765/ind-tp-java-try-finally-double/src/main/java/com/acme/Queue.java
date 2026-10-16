package com.acme;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

public class Queue {
    private final ReentrantLock lock = new ReentrantLock();
    private final List<String> items = new ArrayList<>();

    public String take() {
        lock.lock();
        try {
            if (items.isEmpty()) {
                lock.unlock();
                return null;
            }
            return items.remove(0);
        } finally {
~>            lock.unlock();
        }
    }
}
