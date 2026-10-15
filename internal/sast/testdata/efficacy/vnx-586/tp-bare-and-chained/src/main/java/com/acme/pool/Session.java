package com.acme.pool;

public class Session {
    void close() throws Throwable {
~>        finalize();
    }

    void dispose(Session other) throws Throwable {
        other
~>            .finalize();
    }
}
