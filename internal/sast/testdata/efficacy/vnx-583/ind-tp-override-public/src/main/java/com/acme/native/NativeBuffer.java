package com.acme.nativeio;

public class NativeBuffer implements AutoCloseable {
    private long address;

    public NativeBuffer(int size) {
        this.address = Unsafe.allocate(size);
    }

    @Override
    public void close() {
        Unsafe.free(address);
        address = 0;
    }

~>    @Override public void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
}
