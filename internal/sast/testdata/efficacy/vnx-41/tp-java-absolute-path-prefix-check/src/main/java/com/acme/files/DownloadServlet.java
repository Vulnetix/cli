package com.acme.files;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DownloadServlet {
    private static final String ROOT = "/srv/files";
    private final Path base = Paths.get(ROOT);

    File open(String name) {
        File f = new File(ROOT, name);
~>        if (!f.getAbsolutePath().startsWith(ROOT)) {
            throw new SecurityException("outside root");
        }
        return f;
    }

    byte[] read(String name) throws Exception {
        Path target = base.resolve(name);
~>        if (!target.startsWith(base)) {
            throw new SecurityException("outside root");
        }
        return Files.readAllBytes(target);
    }

    boolean allowed(String name) {
        String p = new File(ROOT + "/" + name).getPath();
~>        return p.startsWith(ROOT);
    }
}
