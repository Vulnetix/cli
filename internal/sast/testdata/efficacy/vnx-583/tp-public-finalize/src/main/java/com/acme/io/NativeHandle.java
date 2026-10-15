package com.acme.io;

public class NativeHandle {
    private long ptr;

    @Override
~>    public void finalize() throws Throwable {
        release(ptr);
        super.finalize();
    }

    private static native void release(long p);
}
