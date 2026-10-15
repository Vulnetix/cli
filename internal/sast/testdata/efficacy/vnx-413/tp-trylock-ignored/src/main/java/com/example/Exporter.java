package com.example;

import java.nio.channels.FileChannel;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Exporter {
    private final Lock exportLock = new ReentrantLock();

    public void export(FileChannel channel) throws Exception {
~>        exportLock.tryLock();
        try {
            write();
        } finally {
            exportLock.unlock();
        }
~>        channel.tryLock();
        channel.write(buffer());
    }
}
