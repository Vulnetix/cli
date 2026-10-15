package com.acme.io;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class Journal implements AutoCloseable {
    private final BufferedWriter writer;

    public Journal(String path) throws IOException {
        FileWriter fw = new FileWriter(path, true);
        this.writer = new BufferedWriter(fw);
    }

    public void append(String line) throws IOException {
        writer.write(line);
        writer.newLine();
    }

    @Override
    public void close() throws IOException {
        writer.close();
    }
}
