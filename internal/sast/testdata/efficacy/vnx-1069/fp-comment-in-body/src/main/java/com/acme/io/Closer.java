package com.acme.io;

import java.io.Closeable;
import java.io.IOException;

public final class Closer {
    public static void closeQuietly(Closeable c) {
        try {
            c.close();
        } catch (IOException e) {
            // closing a read-only stream cannot lose data; nothing to report
        }
    }

    public static void closeAgain(Closeable c) {
        try {
            c.close();
        } catch (IOException e) { /* already reported by the caller */ }
    }
}
