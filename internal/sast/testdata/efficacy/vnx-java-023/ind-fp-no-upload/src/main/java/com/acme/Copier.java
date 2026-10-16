package com.acme;
import java.nio.file.*;
public class Copier {
    void backup(Path src) throws Exception {
        Files.copy(src, Paths.get("/backup/" + src.getFileName()));
    }
}
