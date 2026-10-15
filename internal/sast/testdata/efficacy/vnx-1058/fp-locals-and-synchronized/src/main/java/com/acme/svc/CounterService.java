package com.acme.svc;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;

@Service
public class CounterService {
    private static int count;
    private static List<String> names = new ArrayList<>();
    private static final ReentrantLock LOCK = new ReentrantLock();

    public static synchronized void increment() {
        count++;
    }

    public void addName(String n) {
        LOCK.lock();
        try {
            names.add(n);
        } finally {
            LOCK.unlock();
        }
    }

    public int local() {
        int count = 0;
        // count++ is only done under the lock
        String names = "x";
        return count + names.length();
    }
}
