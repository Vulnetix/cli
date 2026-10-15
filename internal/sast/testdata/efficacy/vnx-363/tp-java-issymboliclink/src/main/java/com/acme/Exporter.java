package com.acme;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public class Exporter {
    public void export(Path out, byte[] body) throws Exception {
        if (Files.isSymbolicLink(out)) {
            throw new SecurityException("link");
        }
~>        Files.write(out, body);
    }

    public void legacy(Path target, byte[] body) throws Exception {
        if (!Files.isSymbolicLink(target)) {
~>            try (FileOutputStream fos = new FileOutputStream(target.toFile())) {
                fos.write(body);
            }
        }
    }
}
