package com.acme.jobs;

import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Exporter {
    private final Lock lock = new ReentrantLock();

    public boolean export(String path, String body) throws IOException {
        if (lock.tryLock()) {
            try {
                write(path, body);
            } finally {
                lock.unlock();
            }
            return true;
        }
        return false;
    }

    private void write(String path, String body) throws IOException {
        FileWriter w = new FileWriter(path);
        try {
            w.write(body);
        } finally {
            w.close();
        }
    }
}
