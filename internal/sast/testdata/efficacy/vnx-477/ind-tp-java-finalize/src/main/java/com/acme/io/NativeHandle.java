package com.acme.io;

public class NativeHandle {
    private long ptr;

    @Override
~>    protected void finalize() throws Throwable {
        release(ptr);
    }

    private static native void release(long p);
}
