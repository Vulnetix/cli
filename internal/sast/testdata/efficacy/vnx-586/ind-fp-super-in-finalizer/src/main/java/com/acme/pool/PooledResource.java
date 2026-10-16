package com.acme.pool;

public class PooledResource {
    private long ptr;

    @Override
    protected void finalize() throws Throwable {
        try {
            Native.free(ptr);
        } finally {
            super.finalize();
        }
    }
}
