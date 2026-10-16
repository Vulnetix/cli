package app;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

public class Good {
    private final ReentrantLock lock = new ReentrantLock();

    void a() {
        lock.lock();
        try {
            work();
        } finally {
            lock.unlock();
        }
    }

    void b() throws InterruptedException {
        if (lock.tryLock(1, TimeUnit.SECONDS)) {
            try {
                work();
            } finally {
                lock.unlock();
            }
        }
    }

    void c() {
        boolean acquired = lock.tryLock();
        try {
            work();
        } finally {
            if (acquired) lock.unlock();
        }
    }

    void work() {
        // lock.tryLock(); lock.unlock();
        String s = "lock.unlock()";
    }
}
