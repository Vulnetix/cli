package com.acme.pool;

public class Resource {
    @Override
    protected void finalize() throws Throwable {
        try {
            release();
        } finally {
            super.finalize();
        }
    }

    void release() {}
}
