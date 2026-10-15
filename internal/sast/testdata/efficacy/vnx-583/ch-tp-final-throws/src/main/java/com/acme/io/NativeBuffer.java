package com.acme.io;

public class NativeBuffer {
    private long handle;

~>    public final void finalize() throws Throwable {
        release(handle);
    }

    private static native void release(long h);
}
