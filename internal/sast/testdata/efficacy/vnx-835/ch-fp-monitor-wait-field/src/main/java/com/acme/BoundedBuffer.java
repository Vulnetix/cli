package com.acme;

public class BoundedBuffer {
    private final Object[] items;
    private final int capacity;
    private int count;
    private int head;

    public BoundedBuffer(int capacity) {
        this.capacity = capacity;
        this.items = new Object[capacity];
    }

    public synchronized void put(Object o) throws InterruptedException {
        while (count >= capacity) {
            wait();
        }
        items[(head + count) % capacity] = o;
        count++;
        notifyAll();
    }

    public void awaitDrained() throws InterruptedException {
        while (count > 0) {
            Thread.sleep(10);
        }
    }
}
