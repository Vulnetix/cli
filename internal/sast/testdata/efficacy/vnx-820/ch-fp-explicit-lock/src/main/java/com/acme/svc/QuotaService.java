package com.acme.svc;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;

@Service
public class QuotaService {
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<String, Integer> used = new HashMap<>();
    private int total;

    public void consume(String tenant, int n) {
        lock.lock();
        try {
            used.merge(tenant, n, Integer::sum);
            total += n;
        } finally {
            lock.unlock();
        }
    }
}
