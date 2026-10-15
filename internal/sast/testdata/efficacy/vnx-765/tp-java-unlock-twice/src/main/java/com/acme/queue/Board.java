package com.acme.queue;

import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Board {
    private final ReentrantReadWriteLock rw = new ReentrantReadWriteLock();

    public void post(String m) {
        rw.writeLock().lock();
        messages.add(m);
        rw.writeLock().unlock();
        notifyListeners();
~>        rw.writeLock().unlock();
    }
}
