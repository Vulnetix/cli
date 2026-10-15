package com.acme.io;

import java.io.Closeable;
import java.io.IOException;

public final class Streams {
    private Streams() {}

    public static void closeQuietly(Closeable c) {
        try {
            c.close();
        } catch (IOException ignored) {
        }
    }

    public static void closeAll(Closeable a, Closeable b) {
        try {
            a.close();
        } catch (IOException e) {
            // closing a read-only stream cannot lose data; nothing to report
        }
        try { b.close(); } catch (IOException expected) {}
    }

    public static Runnable noop() {
        return () -> {};
    }
}
