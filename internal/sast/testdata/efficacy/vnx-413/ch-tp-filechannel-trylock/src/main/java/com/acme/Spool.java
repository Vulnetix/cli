package com.acme;

import java.nio.channels.FileChannel;

public class Spool {
    public void write(FileChannel channel, byte[] data) throws Exception {
~>        channel.tryLock(0L, Long.MAX_VALUE, false);
        channel.write(java.nio.ByteBuffer.wrap(data));
    }
}
