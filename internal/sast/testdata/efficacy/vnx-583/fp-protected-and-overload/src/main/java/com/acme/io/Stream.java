package com.acme.io;

public class Stream {
    @Override
    protected void finalize() throws Throwable {
        super.finalize();
    }

    public void finalize(int code) {
        System.out.println(code);
    }

    public void finalizeOrder() {
    }

    public static void finalizeAll() {
    }
}
