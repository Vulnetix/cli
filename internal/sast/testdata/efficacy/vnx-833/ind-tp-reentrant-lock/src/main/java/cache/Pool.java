package cache;

import java.util.concurrent.locks.ReentrantLock;

public class Pool {
    private final ReentrantLock readLock = new ReentrantLock();
    private final ReentrantLock writeLock = new ReentrantLock();

    public void evict() {
        readLock.lock();
        try {
~>            writeLock.lock();
            try {
                drop();
            } finally {
                writeLock.unlock();
            }
        } finally {
            readLock.unlock();
        }
    }

    public void refill() {
        writeLock.lock();
        try {
~>            readLock.lock();
            try {
                load();
            } finally {
                readLock.unlock();
            }
        } finally {
            writeLock.unlock();
        }
    }
}
