package com.acme;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.locks.ReentrantLock;

public class Dispatcher {
    private final ReentrantLock queueLock = new ReentrantLock(true);
    private final Deque<Task> queue = new ArrayDeque<>();

    public Task next() throws InterruptedException {
~>        queueLock.lockInterruptibly();
        Task t = queue.pollFirst();
        t.markClaimed();
        queueLock.unlock();
        return t;
    }
}
