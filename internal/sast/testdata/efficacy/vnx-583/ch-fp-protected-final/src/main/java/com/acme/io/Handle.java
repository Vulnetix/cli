package com.acme.io;

public class Handle {
    @Override
    protected final void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    public void finalizeWrites() {}
    public boolean finalized() { return true; }
    public void finalize(String reason) {}
    public void close() {}
}
