package com.acme.io;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class Copier {
    public void copy(String from, String to) throws IOException {
        try (FileInputStream in = new FileInputStream(from);
             FileOutputStream out = new FileOutputStream(to)) {
            in.transferTo(out);
        }
    }

    public int peek(String from) throws IOException {
        FileInputStream in = new FileInputStream(from);
        try (in) {
            return in.read();
        }
    }
}
