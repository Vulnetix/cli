package com.acme.report;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

public class LineCounter {
    public long count(Path path) throws IOException {
~>        Stream<String> lines = Files.lines(path);
        return lines.filter(l -> !l.isBlank()).count();
    }

    public int firstByte(String name) throws IOException {
~>        var in = new FileInputStream(name);
        return in.read();
    }
}
