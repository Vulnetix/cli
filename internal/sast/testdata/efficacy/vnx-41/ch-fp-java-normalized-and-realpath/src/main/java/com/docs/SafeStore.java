package com.docs;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SafeStore {
    private final Path base = Paths.get("/var/docs").toAbsolutePath().normalize();

    public Path locate(String name) {
        Path p = base.resolve(name).normalize();
        if (!p.startsWith(base)) {
            throw new SecurityException("outside docs");
        }
        return p;
    }

    public File locateFile(String name) throws IOException {
        File f = new File(base.toFile(), name);
        String canonical = f.getCanonicalPath();
        if (!canonical.startsWith(base.toString() + File.separator)) {
            throw new SecurityException("outside docs");
        }
        return f;
    }

    public boolean isSecure(String url) {
        String full = "https://" + url;
        return full.startsWith("https://");
    }
}
