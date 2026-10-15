package com.acme.io;

import java.io.IOException;
import java.util.logging.Logger;

public class Reader {
    private static final Logger LOG = Logger.getLogger("reader");

    public byte[] read(java.io.InputStream in) {
        try {
            return in.readAllBytes();
        } catch (IOException e) {
            LOG.warning("read failed: " + e.getMessage());
            return new byte[0];
        }
    }

    public int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("not a number: " + s, e);
        }
    }

    public void sleep() {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public String msg(Exception e) {
        try {
            return e.toString();
        } catch (RuntimeException r) {
            return "unknown";
        }
    }
}
