package com.acme.io;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class LockManager {
    public File lockFile() {
        String tmpDir = System.getProperty("java.io.tmpdir");
~>        return new File(tmpDir, "acme-app.lock");
    }

    public Path cache() {
~>        return Paths.get(System.getProperty("java.io.tmpdir"), "acme-cache.bin");
    }
}
