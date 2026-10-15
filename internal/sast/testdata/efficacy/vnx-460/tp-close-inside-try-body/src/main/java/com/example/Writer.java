package com.example;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class Writer {
    public void write(String path, String text) {
        BufferedWriter out = null;
        try {
~>            out = new BufferedWriter(new FileWriter(path));
            out.write(text);
            out.close();
        } catch (IOException e) {
            System.err.println("write failed: " + e.getMessage());
        }
    }
}
