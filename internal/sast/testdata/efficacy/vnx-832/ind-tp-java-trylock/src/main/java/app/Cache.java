package app;

import java.util.concurrent.locks.ReentrantLock;

public class Cache {
    private final ReentrantLock lock = new ReentrantLock();

    void refresh() {
        lock.tryLock();
        try {
            reload();
        } finally {
~>            lock.unlock();
        }
    }

    void put(String k, String v) throws InterruptedException {
        try {
            lock.lockInterruptibly();
            data(k, v);
        } finally {
~>            lock.unlock();
        }
    }

    void reload() {}
    void data(String k, String v) {}
}
