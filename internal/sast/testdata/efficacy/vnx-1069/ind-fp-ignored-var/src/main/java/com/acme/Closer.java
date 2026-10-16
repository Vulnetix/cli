package com.acme;
import java.io.*;
public class Closer {
    void quiet(Closeable c) {
        try { c.close(); } catch (IOException ignored) {}
        try { c.close(); } catch (IOException ignore) { }
        try { c.close(); } catch (IOException _) {}
        try { Integer.parseInt("x"); } catch (NumberFormatException expected) {}
    }
}
