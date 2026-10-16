package com.acme.tx;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.locks.ReentrantLock;

public class Transaction {
    private final ReentrantLock lock = new ReentrantLock();

    public void begin() {
        lock.lock();
    }

    public void end() {
        lock.unlock();
    }

    public Properties parse(byte[] raw) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(raw);
        Properties p = new Properties();
        p.load(in);
        in.close();
        return p;
    }
}
