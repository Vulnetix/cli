package com.acme.archive;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipFile;

public class StreamUnzip {
    public void extract(Path archive, Path target) throws IOException {
        try (ZipFile zf = new ZipFile(archive.toFile())) {
            zf.stream().filter(e -> !e.isDirectory()).forEach(e -> {
~>                Path out = target.resolve(e.getName());
                try (InputStream in = zf.getInputStream(e)) {
                    Files.createDirectories(out.getParent());
                    Files.copy(in, out);
                } catch (IOException ex) {
                    throw new UncheckedIOException(ex);
                }
            });
        }
    }
}
