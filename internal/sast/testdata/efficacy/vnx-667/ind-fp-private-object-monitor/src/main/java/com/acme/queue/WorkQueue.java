package com.acme.queue;

import java.util.ArrayDeque;
import java.util.Deque;

public class WorkQueue {
    private final Object lock = new Object();
    private final Deque<Runnable> tasks = new ArrayDeque<>();
    private String name = "default";

    public void push(Runnable r) {
        synchronized (lock) {
            tasks.addLast(r);
            lock.notifyAll();
        }
    }

    public synchronized int size() {
        synchronized (this) {
            return tasks.size();
        }
    }

    public static void init() {
        synchronized (WorkQueue.class) {
            // "synchronized (\"LOCK\")" would share the monitor JVM-wide
        }
    }
}
