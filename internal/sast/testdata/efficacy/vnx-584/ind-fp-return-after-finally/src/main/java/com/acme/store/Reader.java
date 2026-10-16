package com.acme.store;

import java.io.BufferedReader;
import java.io.IOException;

public class Reader {
    public String firstLine(BufferedReader r) throws IOException {
        String line;
        try {
            line = r.readLine();
        } catch (IOException e) {
            return null;
        } finally {
            r.close();
        }
        return line;
    }

    public int tryReturn() {
        try {
            return compute();
        } finally {
            cleanup();
        }
    }
}
