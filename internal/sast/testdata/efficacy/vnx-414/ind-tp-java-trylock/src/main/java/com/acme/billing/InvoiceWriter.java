package com.acme.billing;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.concurrent.locks.ReentrantLock;

public class InvoiceWriter {
    private final ReentrantLock lock = new ReentrantLock();
    private long written;

    public void append(FileChannel channel, byte[] record) throws IOException {
~>        lock.tryLock();
        try {
~>            channel.tryLock();
            channel.write(java.nio.ByteBuffer.wrap(record));
            written += record.length;
        } finally {
            lock.unlock();
        }
    }
}
