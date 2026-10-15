package com.acme.util;

import java.io.Closeable;
import java.io.IOException;

public final class Closer {
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
            // best effort: the stream is already being discarded
        }
        try {
            b.close();
        } catch (IOException expected) {}
        try {
            b.close();
        } catch (IOException _) {
        }
    }
}
