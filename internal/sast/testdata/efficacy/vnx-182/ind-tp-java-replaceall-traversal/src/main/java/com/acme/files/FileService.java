package com.acme.files;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileService {

    private final Path base = Paths.get("/data/uploads");

    public byte[] read(String requested) throws IOException {
~>        String safe = requested.replaceAll("\\.\\./", "");
        return Files.readAllBytes(base.resolve(safe));
    }
}
