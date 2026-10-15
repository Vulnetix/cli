package com.acme;

public class Cleanup {
    public void close(AutoCloseable c) {
        try {
            c.close();
        } catch (Exception ignored) {
            closed = false;
        }
    }

    public int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
