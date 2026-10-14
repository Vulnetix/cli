package com.example.io;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class LockFile {
    public void write(String user, byte[] data) throws IOException {
~>        File f = new File("/tmp/" + user + ".lock");
~>        try (FileOutputStream out = new FileOutputStream("/tmp/app-upload.bin")) {
            out.write(data);
        }
~>        Path p = Paths.get("/tmp", "session-" + user);
        Files.write(p, data);
~>        try (FileWriter w = new FileWriter("/var/tmp/export.txt")) {
            w.write("x");
        }
~>        Path q = Path.of("/tmp/cache.db");
    }
}
