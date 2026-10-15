package com.acme.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Paths2 {
    public File a() {
        return new File("/tmpfs/acme/data.bin");
    }

    public Path b() {
        return Paths.get("build/tmp/out.txt");
    }

    public void c() throws IOException {
        // new File("/tmp/predictable.txt") is unsafe; use Files.createTempFile
        throw new IOException("cannot write to /tmp/acme.lock");
    }

    public String d() {
        return "Set java.io.tmpdir to a private directory";
    }
}
