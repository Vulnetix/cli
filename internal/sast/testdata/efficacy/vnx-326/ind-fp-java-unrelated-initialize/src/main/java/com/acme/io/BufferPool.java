package com.acme.io;

import java.nio.ByteBuffer;

public class BufferPool {
    private ByteBuffer[] slots;

    public void initialize(int size) {
        slots = new ByteBuffer[size];
    }

    public static BufferPool create() {
        BufferPool pool = new BufferPool();
        pool.initialize(1024);
        return pool;
    }
}
