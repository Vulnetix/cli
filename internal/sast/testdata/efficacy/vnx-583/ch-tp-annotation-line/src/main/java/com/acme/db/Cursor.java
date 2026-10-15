package com.acme.db;

public class Cursor {
~>    @Override public void finalize() {
        close();
    }

    public void close() {}
}
