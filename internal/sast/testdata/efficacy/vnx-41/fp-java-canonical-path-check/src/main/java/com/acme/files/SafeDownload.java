package com.acme.files;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SafeDownload {
    private static final String ROOT = "/srv/files";
    private final Path base = Paths.get(ROOT).toAbsolutePath().normalize();

    File open(String name) throws Exception {
        File f = new File(ROOT, name);
        if (!f.getCanonicalPath().startsWith(new File(ROOT).getCanonicalPath() + File.separator)) {
            throw new SecurityException("outside root");
        }
        return f;
    }

    Path resolve(String name) {
        Path target = base.resolve(name).normalize();
        if (!target.startsWith(base)) {
            throw new SecurityException("outside root");
        }
        return target;
    }

    Path real(String name) throws Exception {
        Path target = base.resolve(name);
        target = target.toRealPath();
        if (!target.startsWith(base)) {
            throw new SecurityException("outside root");
        }
        return target;
    }

    boolean secure(String url) {
        String u = new File(url).getPath();
        return u.startsWith("http");
    }
}
