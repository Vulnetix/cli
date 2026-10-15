package com.acme.io;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public class Copier {
    public byte[] read(String path) throws IOException {
~>        FileInputStream in = new FileInputStream(path);
        return in.readAllBytes();
    }

    public String firstLine(String path) throws IOException {
~>        BufferedReader reader = new BufferedReader(new FileReader(path));
        String line = reader.readLine();
        return line;
    }

    public void append(String path, String text) throws IOException {
~>        FileWriter writer = new FileWriter(path, true);
        writer.write(text);
        writer.flush();
    }

    public long count(Path p) throws IOException {
~>        Stream<String> lines = Files.lines(p);
        return lines.count();
    }
}
